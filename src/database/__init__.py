# from models import Project, ProjectAcl, Secret, SecretAcl, SecretValue, ApiKey, ApiKeySource, AuditLog
import logging
import ipaddress
from fastapi.responses import JSONResponse
from .models import ApiKey, ApiKeySource, Project, ProjectAcl, Secret, SecretAcl, SecretValue, AuditLog
from tortoise.queryset import Q
from tortoise.functions import Count
from .crypto import Crypto

class TortoiseDB:
    def __init__(self, secret_key: str, no_encrypt: bool, token_lock_config: dict):
        self.crypto = Crypto(key=secret_key, no_encrypt=no_encrypt)
        self.token_deny_limit = token_lock_config["token_deny_limit"]
        self.token_deny_minutes = token_lock_config["token_deny_minutes"]
        self.token_lock_minutes = token_lock_config["token_lock_minutes"]
        self.logger = logging.getLogger(__name__)

        ApiKey.set_crypto(self.crypto)
        SecretValue.set_crypto(self.crypto)

    async def __send_error__(self, code: int = 404, message: str = None):
        resp_message = message if message else "Resource not found"
        if code == 404 and not message:
            self.logger.debug("Sending generic 404 response to unauthorized request")
        return JSONResponse(status_code=code, content={"error": f"{resp_message}"})

    async def __create_project__(self, project_data: dict):
        """
        Add or update a project in the database
        return the project_id: int
        """
        project_obj, created = await Project.update_or_create(
            bw_project_id=project_data['id'],
            defaults={
                "name": project_data['name'],
                "bw_organization_id": project_data['organization_id']
            }
        )
        if created and isinstance(project_obj.id, int):
            verb = 'Created' if created else 'Updated'
            self.logger.debug(f"{verb} secret: {project_obj.name},  ID: {project_obj.id}")
        return project_obj.id

    async def __create_secret__(self, secret_data: dict):
        """
        Add or update a secret in the database
        return the secret_id: int
        """
        self.logger.debug(f"Creating secret: {secret_data['key']} for project id: {secret_data['project_id']}")
        try:
            secret_obj, created = await Secret.update_or_create(
                bw_secret_id=secret_data['id'],
                defaults={
                    "key": secret_data['key'],
                    "project": await Project.get(bw_project_id=secret_data['project_id']),
                    "note": f"""{secret_data['note']}"""
                }
            )
            if created and isinstance(secret_obj.id, int):
                verb = 'Created' if created else 'Updated'
                self.logger.debug(f"{verb} secret: {secret_obj.key},  ID: {secret_obj.id}")
            return secret_obj.id
        except Exception as err:
            self.logger.error(f"Failed to create secret: {err}")
            return None

    async def __create_secret_value__(self, secret_id: int, secret_key: str, secret_value: str, section: str = None):
        """
        Add or update a secret value in the database
        return the secret_value_id: int
        """
        try:
            secret_value_obj, created = await SecretValue.update_or_create(
                secret=await Secret.get(id=secret_id),
                key=secret_key,
                defaults={
                    "value": secret_value,
                    "section": section
                }
            )
            if created and isinstance(secret_value_obj.id, int):
                verb = 'Created' if created else 'Updated'
                self.logger.debug(f"{verb} secret value: {secret_value_obj.key},  ID: {secret_value_obj.id}")
            return secret_value_obj.id
        except Exception as err:
            self.logger.error(f"Failed to create secret value: {err}")
            return None

    async def __values_from_values__(self, secret_values: dict, section_key: str = None):
        """
        Convert the secret values from a dict to a list of dicts
        """
        values = []
        for key, value in secret_values.items():
            if isinstance(value, dict):
                values = values + (await self.__values_from_values__(value, section_key=key))
            else:
                values.append({"key": key, "value": value, "section": section_key})
        return values

    async def __clear_all_acls__(self):
        """
        Remove all ACLs from the database for reloading
        """
        await SecretAcl.all().delete()
        await ProjectAcl.all().delete()
        await ApiKeySource.all().delete()
        await ApiKey.all().update(is_active=False)

    async def __create_acl__(self, secret_acl: dict):
        """
        Add or update a secret ACL in the database
        return the secret_acl_id: int
        """
        # Validate the ACL data as a dict
        if not isinstance(secret_acl["value"], dict):
            self.logger.error(f"Invalid ACL data")
            return None

        # Get the project name from the secret key
        project_name = secret_acl["key"].replace("_acl", "")
        try:
            project_obj = await Project.get(name=project_name)
            await project_obj.fetch_related("secrets")
        except Exception as err:
            self.logger.error(f"Failed to get project: {err}")
            return await self.__send_error__()

        # Loop through the API Keys in the ACL
        for api_key, perms in secret_acl["value"].items():
            token_enabled = perms["enabled"] if "enabled" in perms else True
            hashed_token = await ApiKey._crypto.hashstr(api_key.strip())
            # Create/update the API Key
            self.logger.debug(f"Creating ACL for API Key: '{api_key}'")
            api_key_obj, created = await ApiKey.update_or_create(
                token=hashed_token,
                defaults={
                    "is_active": token_enabled,
                    "name": perms["name"] if "name" in perms else "api-token"
                }
            )
            project_acl_obj, created = await ProjectAcl.update_or_create(
                api_key=await ApiKey.get(token=hashed_token),
                project=await Project.get(name=project_name)
            )
            # Add ACL entries for the token's associates secret(s)
            if "secrets" in perms:
                for secret_key in perms["secrets"]:
                    if secret_key == "*":
                        # Use all the secrets for the project if the secret key is *
                        secret_objs = project_obj.secrets
                    else:
                        # Get the secret by key or bw_secret_id
                        secret_objs = await Secret.filter(
                            Q(project=project_obj) &
                            (Q(bw_secret_id=secret_key) | Q(key=secret_key))
                        ).all()
                    # Add the secret(s) to the ACL
                    if secret_objs:
                        for secret_obj in secret_objs:
                            await SecretAcl.update_or_create(
                                secret=secret_obj,
                                api_key=api_key_obj
                            )
            # Add ACL allowed sources to the token's ACL
            if "sources" in perms:
                for source in perms["sources"]:
                    # Verify that the source is a valid IP CIDR
                    try:
                        if source == "*":
                            valid_source = ipaddress.ip_network("0.0.0.0/0")
                        else:
                            valid_source = ipaddress.ip_network(source)
                    except ValueError:
                        self.logger.error(f"Invalid IP CIDR: '{source}'. Dropped from ACL")
                        continue
                    self.logger.debug(f"Adding source: '{valid_source}' to API Key: '{api_key_obj.name}'")
                    await ApiKeySource.update_or_create(
                        api_key=api_key_obj,
                        source_cidr=valid_source
                    )

    async def load_bws_secrets(self, secret_data: dict):

        if "projects" not in secret_data or "secrets" not in secret_data:
            raise ValueError("Invalid Bitwarden Secrets Manager data")

        self.logger.debug(f"Loading {len(secret_data['projects'])} projects and {len(secret_data['secrets'])} secrets from Bitwarden Secrets Manager")

        for project in secret_data['projects']:
            await self.__create_project__(project_data=project)

        secret_acls = []
        for secret in secret_data['secrets']:
            # Save the ACLs for later processing
            if secret["key"].endswith("_acl"):
                self.logger.debug(f"Found ACL secret: '{secret['key']}'")
                secret_acls.append(secret)
                continue

            secret_id = await self.__create_secret__(
                secret_data=secret,
            )

            if secret_id and "value" in secret:
                self.logger.debug(f"Setting secret value(s) for secret: '{secret['key']}'")
                if isinstance(secret['value'], dict):
                    values = await self.__values_from_values__(secret['value'])
                    for value in values:
                        await self.__create_secret_value__(
                            secret_id=secret_id,
                            secret_key=value['key'],
                            secret_value=value['value'],
                            section=value['section']
                        )
                else:
                    await self.__create_secret_value__(
                        secret_id=secret_id,
                        secret_key=secret['key'],
                        secret_value=f"""{secret['value']}"""
                    )

        # Clear all ACLs from the database
        await self.__clear_all_acls__()
        # Create ACL entries for each ACL secret
        if len(secret_acls) > 0:
            self.logger.debug(f"Creating ACLs for {len(secret_acls)} ACL secrets")
            for secret_acl in secret_acls:
                await self.__create_acl__(secret_acl)
        else:
            self.logger.debug(f"No ACLs to create")
        return True


    async def get_secret(self, secret_id: str, api_token: str, source_ip: str, debug: bool = False):
        """
        Get a secret value by secret_id or secret key
        """
        hashed_token = await ApiKey._crypto.hashstr(api_token.strip())
        source_ip = source_ip.strip()
        secret_obj = None
        api_key_obj = None
        secret_acl_obj = None
        source_acls = None
        all_values = []

        audit_log = await AuditLog.create(
            secret_key=secret_id,
            source_ip=source_ip,
            token_hash=hashed_token,
            token_name=None,
            acl_pass=False,
            extra="",
        )

        # Get the secret by secret_id or key to verify it is a valid secret
        secret_obj = await Secret.filter(
            Q(bw_secret_id=secret_id) | Q(key=secret_id)
        ).first()
        # If no secret was found, return a 404
        if not secret_obj:
            audit_log.extra = f"Invalid secret_id or key: {secret_id}"
            await audit_log.save()
            return await self.__send_error__()

        # Check if the API Key is allowed to access the secret
        try:
            api_key_obj = await ApiKey.get(token=hashed_token, is_active=True)
            lock_status = await ApiKey.check_and_update_lock_status(
                api_key_obj,
                token_deny_limit=self.token_deny_limit,
                token_deny_minutes=self.token_deny_minutes,
                token_lock_minutes=self.token_lock_minutes
            )
            if lock_status:
                self.logger.info(f"API Key: {api_key_obj.name} has been {lock_status}")
            if api_key_obj.is_locked:
                emsg = f"API Key is currently locked"
                self.logger.error(emsg)
                audit_log.extra = emsg
                await audit_log.save()
                if not debug:
                    return await self.__send_error__()
                else:
                    return await self.__send_error__(code=401, message=emsg)
            self.logger.debug(f"API Key: {api_key_obj.name} is valid and active")
        except Exception as err:
            emsg = f"API Key disabled or not found: {err}"
            self.logger.error(emsg)
            audit_log.extra = emsg
            await audit_log.save()
            if not debug:
                return await self.__send_error__()
            else:
                return await self.__send_error__(code=401, message="Invalid API Token")

        # Save the secret_id and api token name to the audit log
        audit_log.secret_key = secret_obj.key
        audit_log.token_name = api_key_obj.name
        await audit_log.save()

        # Get the ACL for the api_key and secret. exception if not found
        try:
            secret_acl_obj = await SecretAcl.get(secret=secret_obj, api_key=api_key_obj)
            self.logger.debug(f"API Key: {api_key_obj.name} is allowed to access secret: {secret_obj.key}")
        except Exception as err:
            emsg = f"API Token not allowed to access secret: {secret_obj.key}"
            self.logger.error(f"Failed to get secret ACL: {err}")
            audit_log.extra = emsg
            await audit_log.save()
            if not debug:
                return await self.__send_error__()
            else:
                return await self.__send_error__(
                    code=401,
                    message=emsg
                )

        # Verify the source IP is allowed to access the secret
        # Fetch all the source ACLs for the API Key
        try:
            source_acls = await ApiKeySource.filter(api_key=api_key_obj).all()
        except Exception as err:
            emsg = "Source IP not allowed to access secret: {secret_obj.key}"
            self.logger.error(f"Failed to get ACL allowed sources: {err}")
            audit_log.extra = emsg
            await audit_log.save()
            if not debug:
                return await self.__send_error__()
            else:
                return await self.__send_error__(code=401, message=emsg)

        # Check if the source IP is allowed to access the secret by comparing the source IP to the allowed CIDRs
        source_allowed = False
        for source_acl in source_acls:
            if ipaddress.ip_address(source_ip) in ipaddress.ip_network(source_acl.source_cidr):
                self.logger.debug(f"Source IP: '{source_ip}' is allowed to access secret by ACL CIDR: '{source_acl.source_cidr}'")
                source_allowed = True
                break

        if not source_allowed:
            emsg = f"Source IP: '{source_ip}' not allowed to access secret: {secret_obj.key}"
            self.logger.error(emsg)
            audit_log.extra = emsg
            await audit_log.save()
            if not debug:
                return await self.__send_error__()
            else:
                return await self.__send_error__(
                    code=401,
                    message=emsg
                )

        # ACL Check passed. Get the secret values
        await secret_obj.fetch_related("values")
        # Sort the values by section
        secret_values = await secret_obj.values.filter().order_by('section')
        # Create the output dictionary
        output = {"secret_key": f"{secret_obj.key}", "values": [], "sections": {}}
        for value in secret_values:
            if value.section:
                if value.section not in output["sections"]:
                    output["sections"][value.section] = []
                output_values = output["sections"][value.section]
            else:
                output_values = output["values"]

            output_values.append(value.as_dict)

        if len(output["values"]) == 0:
            del output["values"]
        if len(output["sections"]) == 0:
            del output["sections"]

        audit_log.acl_pass = True
        await audit_log.save()

        # return a dict of the secret values for the secret
        # The data will be formatted by the ReturnFormat class
        return output


