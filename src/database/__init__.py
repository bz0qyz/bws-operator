# from models import Project, ProjectAcl, Secret, SecretAcl, SecretValue, ApiKey, ApiKeySource, AuditLog
import logging
import ipaddress
from fastapi.responses import JSONResponse
from .models import ApiKey, ApiKeySource, Project, ProjectAcl, Secret, SecretAcl, SecretValue
from .crypto import Crypto

class TortoiseDB:
    def __init__(self, secret_key: str, no_encrypt: bool):
        self.crypto = Crypto(key=secret_key, no_encrypt=no_encrypt)
        self.logger = logging.getLogger(__name__)

        ApiKey.set_crypto(self.crypto)
        SecretValue.set_crypto(self.crypto)

    async def insert_acl(self, api_model):
        api_model.token = self.crypto.hashstr(api_model.token.strip())
        api_key_obj, created = await ApiKey.update_or_create(
            token=api_model.token,
            defaults={"is_active": api_model.is_active}
        )
        verb = 'Created' if created else 'Updated'

        # if api_model.secrets and len(api_model.secrets) > 0:
        #     for secret in api_model.secrets:
        #         secret_id = self.crypto.hashstr(secret.strip())
        #         secret_obj = await Secret.get_or_none(bw_secret_id=secret_id)
        #         if secret_obj:
        #             await SecretAcl.update_or_create(
        #                 secret_id=secret_obj.id,
        #                 api_key_id=api_key.id
        #             )

        return JSONResponse(status_code=201, content={"message": f"ACL {api_key_obj.id} {verb} successfully."})

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
        # self.logger.debug(f"Creating secret value for secret id: {secret_id}")
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

    async def load_bws_secrets(self, secret_data: dict):
        if "projects" not in secret_data or "secrets" not in secret_data:
            raise ValueError("Invalid Bitwarden Secrets Manager data")

        self.logger.debug(f"Loading {len(secret_data['projects'])} projects and {len(secret_data['secrets'])} secrets from Bitwarden Secrets Manager")

        for project in secret_data['projects']:
            await self.__create_project__(project_data=project)


        for secret in secret_data['secrets']:
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
                        secret_value=secret['value']
                    )

        return True

