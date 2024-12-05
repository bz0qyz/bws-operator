import os
import json
import logging
import tempfile
import sqlite3
import uuid
import base64
from cryptography.fernet import Fernet
from bitwarden_sdk import BitwardenClient, DeviceType, schemas, client_settings_from_dict

class BWClient:
    BW_STATE_UNATHENTICATED = 0
    BW_STATE_ATHENTICATED = 1
    BW_STATE_CACHE_READY = 2
    BW_CACHE_TABLES = [
        {"name": "project", "schema": "CREATE TABLE project(id PRIMARY KEY, organization_id, name)"},
        {"name": "secret", "schema": "CREATE TABLE secret(id PRIMARY KEY, organization_id, project_id, key, value, note)"},
        {"name": "secret_value", "schema": "CREATE TABLE secret_value(id INTEGER PRIMARY KEY, secret_id, key, value)"}
    ]
    CACHE_KEY = Fernet.generate_key()

    def __init__(self, api_url:str, id_url: str):
        self.logger = logging.getLogger(__name__)
        self.temp_dir = tempfile.gettempdir()
        self.oper = Fernet(self.CACHE_KEY)
        self.__state_file__ = None
        self.__cachedb__ = os.path.join(self.temp_dir, f".bws.db")
        self.__cache_con__ = sqlite3.connect(
            database=self.__cachedb__,
            isolation_level="EXCLUSIVE",
            autocommit=True
            )
        self.__cache_con__.row_factory = sqlite3.Row
        if not self.__cache_con__:
            raise Exception("Failed to connect to cache database")
        self.__cache_cur__ = self.__cache_con__.cursor()
        self.__create_cache_tables__(self.BW_CACHE_TABLES)
        

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
    def __oper_util__(self, in_data, encode=True):
        """ Store value data securely """
        if encode:
            # print(f"encrypting str: {in_data}")
            return base64.b64encode(self.oper.encrypt(f"{in_data}".encode("utf-8"))).decode("utf-8")
        else:
            # print(f"decrypting str: {in_data}")
            decoded_data = base64.b64decode(in_data)
            return self.oper.decrypt(decoded_data).decode("utf-8")


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

    def __pre_check__(self):
        """ Pre check verification before making any API calls """
        if self.state == self.BW_STATE_UNATHENTICATED:
            raise ValueError("The client is not authenticated.")

        if self.state == self.BW_STATE_CACHE_READY:
            return True
        
        return False
    
    def __create_cache_tables__(self, tables: list):
        for table in tables:
            try:
                self.logger.debug(f"Creating cache table: {table['name']}")
                self.__cache_cur__.execute(table["schema"])
            except sqlite3.OperationalError as err:
                self.logger.debug(f"Dropping cache table: {table['name']}, because it already exists")
                self.__cache_cur__.execute(f"DROP TABLE {table['name']}")
                self.__create_cache_tables__([table])


    def __insert_cache_secret_value__(self, secret_data):
        """ Create secret values from a json secret (if json) """
        try:
            secret_value = json.loads(secret_data['value'])
        except:
            secret_value = secret_data['value']

        if isinstance(secret_value, str):
            query = f"""
            INSERT INTO secret_value (secret_id, key, value) 
            VALUES ('{secret_data['id']}', '{secret_data['key']}', '{self.__oper_util__(secret_data['value'])}')
            """
            self.__cache_cur__.execute(query)
        elif isinstance(secret_value, dict):
            for key, value in secret_value.items():
                query = f"""
                INSERT INTO secret_value (secret_id, key, value) 
                VALUES ('{secret_data['id']}', '{key}', '{self.__oper_util__(value)}')
                """
                self.__cache_cur__.execute(query)


    def __insert_cache_secret__(self, table: str, data: dict):
        keys = []
        values = []
        if table == 'secret':
            self.__insert_cache_secret_value__(secret_data=data)
        for key, value in data.items():
            keys.append(key)
            if isinstance(value, str):
                if key == "value":
                    values.append(f"'{self.__oper_util__(value)}'")
                else:
                    values.append(f"'{value}'")
            elif isinstance(value, uuid.UUID):
                values.append(f"'{value}'")
            else:
                values.append(value)

        query = f"INSERT OR REPLACE INTO {table} ({','.join(keys)}) VALUES ({','.join(values)})"
        self.__cache_cur__.execute(query)


    def __get_cache_data__(self, data_type: str, organization_id: str=None):
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
                'id':str(item.id),
                'organization_id': str(item.organization_id)
                })

        return data

    def __get_secret_by_id__(self, secret_id: str):
        """
        Get a single secret's value by id
        returns: string or dict (if the value is json)
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

        # Drop unused keys
        for key in drop_keys:
            if key in response_data:
                del(response_data[key])
        return response_data


    def __get_cache_secrets__(self, where: str):
        """ Get a secret and it value(s) from cache data """
        if not self.__pre_check__():
            return None
        
        return_data = {"secret": None, "values": []}
        return_data = []

        query = f"SELECT id, organization_id, project_id, key, value, note FROM secret WHERE {where}"
        response = self.__cache_cur__.execute(query)
        return_data_secrets = self.__cache_cur__.fetchall()
        # Get the values for each secret and decode them
        for secret in return_data_secrets:
            query = f"SELECT key, value FROM secret_value WHERE secret_id = '{secret['id']}';"
            response = self.__cache_cur__.execute(query)
            values_sql = self.__cache_cur__.fetchall()
            return_data_values = []
            for svalue in values_sql:
                decoded_value = self.__oper_util__(svalue['value'], encode=False)
                return_data_values.append({svalue['key']: decoded_value})
            return_data.append({"secret": secret, "values": return_data_values})
        
        return return_data


    def __get_cache_project_id_by_name__(self, project_name: str):
        query = f"SELECT id, name FROM project WHERE name='{project_name}'"
        response = self.__cache_cur__.execute(query)
        rows = self.__cache_cur__.fetchall()
        if len(rows) < 1:
            return None
        
        return rows[0]['id']

    """
    Public Methods
    """
    def close(self, purge=True):
        """ Clear cach and close connection """
        self.logger.debug("Closing connection.")
        if self.__cache_con__:
                self.__cache_con__.close()
        if purge:
            self.logger.debug("Clearing cache.")
            if os.path.isfile(self.__cachedb__):
                self.__secure_delete__(self.__cachedb__)
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

    def load_cache(self, reload=False):
        """ Load the cache data from BitWarden """
        self.__pre_check__()
        if reload:
            self.state = self.BW_STATE_ATHENTICATED
            self.__create_cache_tables__(self.BW_CACHE_TABLES)
        self.logger.debug("Loading secrets into cache.")
        # Get a list of available projects
        projects = self.__get_cache_data__(data_type='projects')
        for project in projects:
            self.__insert_cache_secret__(
                table='project',
                data=project,
            )
        # Get a list of available secrets
        secrets = self.__get_cache_data__(data_type='secrets')
        for secret in secrets:
            secret_data = self.__get_secret_by_id__(secret['id'])
            self.__insert_cache_secret__(
                table='secret',
                data=secret_data,
            )
        self.state = self.BW_STATE_CACHE_READY


    def get_organization_secrets(self, organization_id: str):
        """
        Get all the secrets from an organization
        returns: list of SecretData objects
        """
        secret_data = self.__get_cache_secrets__(where=f"organization_id='{organization_id}'")
        if len(secret_data) < 1:
            return None
        
        return_list = []
        for secret in secret_data:
            return_list.append(
                SecretData(response=secret["secret"], values=secret["values"])
            )

        return return_list


    def get_project_secrets(self, project_id: str):
        """
        Get all the secrets from a project
        returns: list of SecretData objects
        """
        # Check to see if we got a project name by attempting to lookup it's id
        project_id_lookup = self.__get_cache_project_id_by_name__(project_name=project_id)
        if project_id_lookup:
            project_id = project_id_lookup
        
        secret_data = self.__get_cache_secrets__(where=f"project_id='{project_id}'")
        if len(secret_data) < 1:
            return None
        
        return_list = []
        for secret in secret_data:
            return_list.append(
                SecretData(response=secret["secret"], values=secret["values"])
            )

        return return_list
    

    def get_secret(self, secret_id: str):
        """
        Get a single secret's value
        returns: SecretData object
        """
        secret_data = self.__get_cache_secrets__(where=f"id='{secret_id}' OR key='{secret_id}'")
        if len(secret_data) < 1:
            return None
            
        return SecretData(
            response=secret_data[0]["secret"],
            values=secret_data[0]["values"]
        )
    
        
class SecretData:
    def __init__(self, response: sqlite3.Row, values: list):
        self.key = response['key']
        self.id = str(response['id'])
        self.organization_id = str(response['organization_id'])
        self.project_id = str(response['project_id'])
        self.note = response['note']
        self.values = values