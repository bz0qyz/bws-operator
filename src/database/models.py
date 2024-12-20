from datetime import datetime, timedelta, timezone
from tortoise import fields
from tortoise.models import Model

class ApiKey(Model):
    id = fields.IntField(pk=True)
    token = fields.CharField(max_length=512, unique=True)
    name = fields.CharField(max_length=254)
    is_active = fields.BooleanField(default=True)
    is_locked = fields.BooleanField(default=False)
    locked_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    _crypto = None  # Placeholder for the crypto instance

    @classmethod
    def set_crypto(cls, crypto):
        cls._crypto = crypto

    async def check_and_update_lock_status(self, token_deny_limit, token_deny_minutes, token_lock_minutes):
        return_action = None

        # Disabled if token_deny_limit is 0
        if token_deny_limit == 0:
            return return_action

        current_time = datetime.now(timezone.utc)
        deny_window_start = current_time - timedelta(minutes=token_deny_minutes)
        lock_expiry_time = self.locked_at + timedelta(minutes=token_lock_minutes) if self.locked_at else None

        # Count failed attempts in the past token_deny_minutes
        failed_attempts = await AuditLog.filter(
            token_hash=self.token,  # Assuming token_hash matches the token in AuditLog
            acl_pass=False,
            created_at__gte=deny_window_start,
        ).count()

        if failed_attempts > token_deny_limit:
            # Lock the API key if the threshold is exceeded
            if not self.is_locked:  # Lock only if not already locked
                self.is_locked = True
                self.locked_at = current_time
                await self.save()
                return_action = "locked"
        elif self.is_locked and lock_expiry_time and current_time > lock_expiry_time:
            # Unlock if lock duration has passed and failed attempts are below the threshold
            if failed_attempts <= token_deny_limit:
                self.is_locked = False
                self.locked_at = None
                await self.save()
                return_action = "unlocked"

        return return_action

    class Meta:
        table = "api_key"


class ApiKeySource(Model):
    id = fields.IntField(pk=True)
    api_key = fields.ForeignKeyField("models.ApiKey", related_name="api_key_source")
    source_cidr = fields.CharField(max_length=100)

    class Meta:
        table = "api_key_source"


class Project(Model):
    id = fields.IntField(pk=True)
    bw_project_id = fields.CharField(max_length=254)
    bw_organization_id = fields.CharField(max_length=254)
    name = fields.CharField(max_length=254)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "project"


class ProjectAcl(Model):
    id = fields.IntField(pk=True)
    project = fields.ForeignKeyField("models.Project", related_name="projects", on_delete=fields.CASCADE)
    api_key = fields.ForeignKeyField("models.ApiKey", related_name="api_keys", on_delete=fields.CASCADE)

    class Meta:
        table = "project_acl"

class Secret(Model):
    id = fields.IntField(pk=True)
    project = fields.ForeignKeyField("models.Project", related_name="secrets", on_delete=fields.CASCADE)
    bw_secret_id = fields.CharField(max_length=254)
    key = fields.CharField(max_length=254)
    note = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "secret"

class SecretAcl(Model):
    id = fields.IntField(pk=True)
    secret = fields.ForeignKeyField("models.Secret", related_name="secret_acl")
    api_key = fields.ForeignKeyField("models.ApiKey", related_name="secret_acl")

    class Meta:
        table = "secret_acl"

class SecretValue(Model):
    id = fields.IntField(pk=True)
    secret = fields.ForeignKeyField("models.Secret", related_name="values", on_delete=fields.CASCADE)
    key = fields.CharField(max_length=254)
    value = fields.TextField()
    section = fields.CharField(max_length=254, null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    _crypto = None  # Placeholder for the crypto instance

    @classmethod
    def set_crypto(cls, crypto):
        cls._crypto = crypto

    async def save(self, *args, **kwargs):
        # Encrypt the token before saving
        if self._crypto and self.value:
            self.value = self._crypto.encrypt(self.value.strip())
        await super().save(*args, **kwargs)

    @property
    def decrypted_value(self):
        # Decrypt the value when accessed
        if self._crypto and self.value:
            return self._crypto.decrypt(self.value)
        return self.value

    @property
    def as_dict(self):
        # if self.section is None:
        return {
            "key": self.key,
            "value": self.decrypted_value
        }
    class Meta:
        table = "secret_value"


class AuditLog(Model):
    id = fields.IntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    token_hash = fields.CharField(max_length=512, null=True)
    token_name = fields.CharField(max_length=100, null=True)
    source_ip = fields.CharField(max_length=100)
    secret_key = fields.CharField(max_length=100)
    acl_pass = fields.BooleanField(default=False)
    extra = fields.TextField(null=True)

    class Meta:
        table = "audit_log"
