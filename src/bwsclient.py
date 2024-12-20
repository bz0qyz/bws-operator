import os
import json
import yaml
import logging
import tempfile
from bitwarden_sdk import BitwardenClient, DeviceType, schemas, client_settings_from_dict

class BWClient:
    BW_STATE_UNATHENTICATED = 0
    BW_STATE_ATHENTICATED = 1

    def __init__(self, api_url:str, id_url: str):
        self.logger = logging.getLogger(__name__)
        self.temp_dir = tempfile.gettempdir()
        self.__state_file__ = None
        self.state = self.BW_STATE_UNATHENTICATED
        self.organization_id = None

        # Create the BitwardenClient, which is used to interact with the SDK
        self.client = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": f"{api_url}",
                    "deviceType": DeviceType.SDK,
                    "identityUrl": f"{id_url}",
                    "userAgent": "Python",
                }
            )
        )

    """
    Private Methods
    """
    def __pre_check__(self):
        """ Pre check verification before making any API calls """
        if self.state == self.BW_STATE_UNATHENTICATED:
            raise ValueError("The client is not authenticated.")
        return True

    def __secure_delete__(self, file_path, passes=3):
        """Securely delete a file by overwriting it."""
        if os.path.exists(file_path):
            # Get the file size
            file_size = os.path.getsize(file_path)

            # Overwrite the file with random data multiple times
            with open(file_path, "ba+") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))

            # Remove the file
            if os.path.isfile(file_path):
                os.remove(file_path)
        else:
            raise FileNotFoundError(f"The file {file_path} does not exist.")

    def __get_secret_data__(self, data_type: str, organization_id: str = None):
        """ Set the mappers for organization data """
        data_types = ["projects", "secrets"]
        if not data_type in data_types:
            raise ValueError(f"Invalid data type requested. Valid options are: {','.join(data_types)}")

        self.__pre_check__()
        self.logger.debug(f"Getting all the available {data_type} for the organization")
        if not organization_id:
            organization_id = self.organization_id

        data = []
        response = getattr(self.client, data_type)().list(organization_id=organization_id)
        if not response.success:
            self.logger.error(f"Unable to get organization {data_type}: {response.error_message}")
            return None

        for item in response.data.data:
            key = 'name' if hasattr(item, 'name') else 'key'
            data.append({
                key: getattr(item, key),
                'id': str(item.id),
                'organization_id': str(item.organization_id)
            })

        return data

    def __get_secret_by_id__(self, secret_id: str):
        """
        Get a single secret's value by id
        returns: string or dict (if the value is json or yaml)
        """
        drop_keys = [
            'creation_date',
            'revision_date'
        ]
        self.__pre_check__()

        try:
            secret_response = self.client.secrets().get(id=secret_id)
        except Exception as err:
            self.logger.error(f"Failed to get secret: {err}")
            return None

        if not secret_response.success:
            self.logger.error(f"Failed to get secret: {secret_response.error_message}")
            return None

        response_data = secret_response.data.__dict__

        # Convert UUID to string and convert json or yaml values to dict
        for key, value in response_data.items():
            value_dict = None
            if isinstance(value, schemas.UUID):
                response_data[key] = str(value)
            if key == 'value':
                try:
                    value_dict = json.loads(value)
                except json.JSONDecodeError:
                    pass
                try:
                    value_dict = yaml.safe_load(value)
                except yaml.YAMLError:
                    pass
                # If a dict or list was parsed from the value, save it as the value
                if value_dict and isinstance(value_dict, (dict, list)):
                    response_data[key] = value_dict

        # Drop unused keys
        for key in drop_keys:
            if key in response_data:
                del (response_data[key])

        return response_data


    """
    Public Methods
    """
    def close(self, purge=True):
        if purge:
            if self.__state_file__ and os.path.isfile(self.__state_file__):
                self.__secure_delete__(self.__state_file__)


    def authenticate(self, organization_id: str, access_token: str):
        self.__state_file__ = os.path.join(self.temp_dir, f"{organization_id}.bwstate")
        self.logger.debug(f"Using state file: {self.__state_file__}")

        # Attempt to authenticate with the Secrets Manager Access Token
        try:
            result = self.client.auth().login_access_token(access_token, self.__state_file__)
        except Exception as err:
            self.logger.error(f"Failed to authenticate with Bitwarden: {err}")
            return False

        if result.error_message:
            self.logger.error(f"Failed to authenticate with Bitwarden: {result.error_message}")
            self.state = self.BW_STATE_UNATHENTICATED
            return False

        if result.data.authenticated:
            self.state = self.BW_STATE_ATHENTICATED

        # Save the org ID
        self.organization_id = organization_id

        return True

    def get_secrets(self):

        self.__pre_check__()
        # 1. Get the available projects for the organization
        # 2. Get the available secrets for the organization
        return_payload = {
            'organization_id': self.organization_id,
            'projects': self.__get_secret_data__(data_type='projects'),
            'secrets': []
        }

        secrets_info = self.__get_secret_data__(data_type='secrets')
        secrets = []
        for secret_info in secrets_info:
            secret = self.__get_secret_by_id__(secret_id=secret_info['id'])
            secrets.append(secret)
        return_payload['secrets'] = secrets

        return return_payload


