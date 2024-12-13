import hashlib
from tortoise import fields
from tortoise.models import Model

class ApiKey(Model):
    id = fields.IntField(pk=True)
    token = fields.CharField(max_length=512, unique=True)
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    _crypto = None  # Placeholder for the crypto instance

    @classmethod
    def set_crypto(cls, crypto):
        cls._crypto = crypto

    # async def save(self, *args, **kwargs):
    #     # hash the token before saving
    #     if self.token:
    #         print(f"Hashing token: '{self.token}'")
    #         # self.token = hashlib.sha256(self.token.encode()).hexdigest()
    #         self.token = self._crypto.hashstr(self.token.strip())
    #     await super().save(*args, **kwargs)

    class Meta:
        table = "api_key"

class ApiKeySource(Model):
    id = fields.IntField(pk=True)
    api_key = fields.ForeignKeyField("models.ApiKey", related_name="api_key_source")
    source_ip = fields.CharField(max_length=100)

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
    api_key = fields.ForeignKeyField("models.ApiKey", related_name="project_acls", on_delete=fields.CASCADE)

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
        if self.section is None:
            return {
                "key": self.key,
                "value": self.decrypted_value
            }
        else:
            return {
                "key": self.key,
                "value": self.decrypted_value,
                "section": self.section
            }
    class Meta:
        table = "secret_value"


class AuditLog(Model):
    id = fields.IntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    secret_id = fields.ForeignKeyField("models.Secret", related_name="audit_log")
    api_key_id = fields.ForeignKeyField("models.ApiKey", related_name="audit_log")
    source_ip = fields.CharField(max_length=100)

    class Meta:
        table = "audit_log"
