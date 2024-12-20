from pydantic import BaseModel, Field, root_validator
from typing import Literal
from helpers import RETURN_FORMAT

class HeaderModel(BaseModel):
    x_token: str

class SecretOutputFormat(BaseModel):
    type: Literal[*RETURN_FORMAT.keys()] = Field("json", description="The output format for the response.")
    pyfstr: str = Field(None, description="A python format string. Variables: {key}, {value}. Accept header used for Content-Type.")
    secret_key: bool = Field(True, description="Show the secret key header in the output format.")
    env_export: bool = Field(False, description="Add the 'export' prefix to the 'env' output format.")

    def __str__(self):
        return self.type

class SecretRequest(BaseModel):
    secret_id: str = Field(None, description="A secret ID or secret Key")
    project_id: str = Field(None, description="A project ID or project Name")
    output_format: SecretOutputFormat
    # format: Literal[*RETURN_FORMAT.keys()] = Field("json", description="The output format for the response.")
    # ini_secret_key: bool = Field(True, description="Show the secret key header in 'ini' output format.")
    # env_export: bool = Field(False, description="Add the 'export' prefix to the 'env' output format.")

    @root_validator(pre=True)
    def check_one_field_required(cls, values):
        secret_id = values.get('secret_id')
        project_id = values.get('project_id')

        # Check if neither field is provided
        if not secret_id and not project_id:
            raise ValueError('Either project_id or project_id must be provided')

        return values

class SecretAcl(BaseModel):
    token: str = Field(None, description="The ACL API Key")
    is_active: bool = Field(True, description="Is the ACL active")
    secrets: list[str] = Field(None, description="A list of secret IDs or secret Keys")
    projects: list[str] = Field(None, description="A list of project IDs or project Names")
    sources: list[str] = Field(None, description="A list of source IP CIDRs")
