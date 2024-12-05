import os
import logging
import ipaddress
import json

RETURN_FORMAT = {
    'json': {"type": "application/json"},
    'env': {"type": "text/plain"},
    'ini': {"type": "text/plain"},
    'raw': {"type": "text/plain"},
    'pyfstr': {"type": None}
}
logger = logging.getLogger(__name__)

""" TLS functions """
def use_tls(tls_key: str, tls_cert: str):
    if not tls_key and tls_cert:
        return False
    if not os.path.isfile(tls_key):
        logger.warning(f"TLS Key file '{tls_key}' does not exist.")
        return False
    if not os.path.isfile(tls_cert):
        logger.warning(f"TLS Certificate file '{tls_cert}' does not exist.")
        return False

    logger.info("Enabling TLS on the HTTP Server")
    return True

""" Pre-check functions """
def ip_allowed(ip: str, allowed_cidrs: list):
    # Bypass if there are no allowed IP CIDRs (disabled)
    if len(allowed_cidrs) < 1:
        return True
    logger.debug(f"Validating IP Address: '{ip}' is authorized to use this service.")
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in allowed_cidrs:
            network_obj = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network_obj:
                return True
        logger.warning(f"Blocked invalid IP address: '{ip}'")
        return False
    except ValueError:
        return False
def agent_allowed(user_agent: str, allowed_user_agent: str):
    logger.debug(f"Validating UserAgent: '{user_agent}' is allowed.")
    if user_agent.lower() == allowed_user_agent.lower():
        return True
    logger.warning(f"Blocked invalid UserAgent: '{user_agent}'")
    return False
def valid_token(token: str, bearer_token: list):
    # Bypass if there are no allowed IP CIDRs (disabled)
    if len(bearer_token) < 1:
        return True
    if token in bearer_token:
        return True

    logger.warning(f"Blocked request with invalid API bearer token")
    return False

class ReturnFormat:
    def __init__(self, out_format):
        self.logger = logging.getLogger(__name__)
        self.out_format = out_format.type
        self.ini_secret_key = out_format.secret_key
        self.env_export = out_format.env_export

        self.content_type = RETURN_FORMAT[self.out_format]

    def __str__(self):
        return self.format

   
    def __format_json__(self, out_data):
        return json.dumps(out_data)

    def __format_env__(self, out_data):
        prefix = "export " if self.env_export else ""
        output = []
        for secret_key, secret_value in out_data.items():
            if self.ini_secret_key:
                output.append(f'# [{secret_key}]')
            for secret in secret_value:
                for key, value in secret.items():
                    output.append(f'{prefix}{key}="{value}"')

        return '\n'.join(output) 
    
    def __format_ini__(self, out_data):
        output = []
        for secret_key, secret_value in out_data.items():
            if self.ini_secret_key:
                output.append(f'[{secret_key}]')
            for secret in secret_value:
                for key, value in secret.items():
                    output.append(f'{key} = {value}')

        return '\n'.join(output) 


    def __format_raw__(self, out_data):
        output = []
        for secret_value in out_data:
            for key, value in secret_value.items():
                output.append(value)
        return '\n'.join(output)
    
    def out(self, out_data: dict):
        self.logger.debug(f"Returning data in the format: '{self.out_format}'")
        return getattr(self, f"__format_{self.out_format}__")(out_data)