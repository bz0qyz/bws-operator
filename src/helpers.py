import os
import logging
import json
from fastapi.responses import JSONResponse, PlainTextResponse

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
def agent_allowed(user_agent: str, allowed_user_agent: str):
    logger.debug(f"Validating UserAgent: '{user_agent}' is allowed.")
    if user_agent.lower() == allowed_user_agent.lower():
        return True
    logger.warning(f"Blocked invalid UserAgent: '{user_agent}'")
    return False

class ReturnFormat:
    def __init__(self, out_format):
        self.logger = logging.getLogger(__name__)
        self.out_format = out_format.type if hasattr(out_format, 'type') else 'json'
        self.out_secret_key = out_format.secret_key if hasattr(out_format, 'secret_key') else False
        self.env_export = out_format.env_export if hasattr(out_format, 'env_export') else False
        self.pyfstr = out_format.pyfstr if hasattr(out_format, 'pyfstr') else None

        self.content_type = RETURN_FORMAT[self.out_format]

    def __str__(self):
        return self.format

    def __list_to_dict__(self, in_list: list):
        return {item['key']: item['value'] for item in in_list}

    def __subformat_kv__(self, out_data: dict, delimiter: str = "=",
                         section_prefix: str = "", secret_prefix: str = "", quote: bool = False):
        output = []

        # Output the sections
        if "values" in out_data:
            if self.out_secret_key:
                section_prefix = f'\n{section_prefix}' if len(output) > 1 else f'{section_prefix}'
                output.append(f"{section_prefix}[{out_data['secret_key']}]")
            for secret_value in out_data["values"]:
                if quote:
                    secret_value['value'] = f"'{secret_value["value"]}'"
                output.append(f"{secret_prefix}{secret_value['key']}{delimiter}{secret_value['value']}")

        if "sections" in out_data:
            for section, section_values in out_data["sections"].items():
                section_prefix = f'\n{section_prefix}' if len(output) > 1 else f'{section_prefix}'
                output.append(f"{section_prefix}[{section}]")
                for secret_value in section_values:
                    if quote:
                        secret_value['value'] = f"'{secret_value["value"]}'"
                    output.append(f"{secret_prefix}{secret_value['key']}{delimiter}{secret_value['value']}")

        return output

    def __format_env__(self, out_data):
        prefix = "export " if self.env_export else ""
        output = self.__subformat_kv__(out_data, delimiter="=", secret_prefix=prefix, section_prefix="# ", quote=True)

        return PlainTextResponse(
            status_code=200,
            content='\n'.join(output)
        )

    def __format_ini__(self, out_data):
        output = self.__subformat_kv__(out_data, delimiter=" = ", section_prefix="")

        return PlainTextResponse(
            status_code=200,
            content='\n'.join(output)
        )

    def __format_raw__(self, out_data):
        output = []

        if "values" in out_data:
            for secret_value in out_data["values"]:
                output.append(secret_value['value'])

        return PlainTextResponse(
            status_code=200,
            content='\n'.join(output)
        )

    def __format_json__(self, out_data):
        json_data = {}
        if "values" in out_data:
            if self.out_secret_key:
                json_data[out_data['secret_key']] = self.__list_to_dict__(out_data["values"])
            else:
                json_data = self.__list_to_dict__(out_data["values"])
        if "sections" in out_data:
            for section, section_values in out_data["sections"].items():
                json_data[section] = self.__list_to_dict__(section_values)

        return JSONResponse(
            status_code=200,
            content=json_data
        )

    def __format_pyfstr__(self, out_data):
        if not self.pyfstr:
            return JSONResponse(
                status_code=400,
                content={"error": "No python format string (pyfstr) provided"}
            )

        output = []
        if "values" in out_data:
            secret_values = self.__list_to_dict__(out_data["values"])
            for key, value in secret_values.items():
                output.append(self.pyfstr.format(key=key, value=value))

        if "sections" in out_data:
            for section, section_values in out_data["sections"].items():
                secret_values = self.__list_to_dict__(section_values)
                for key, value in secret_values.items():
                    output.append(self.pyfstr.format(key=key, value=value))

        return PlainTextResponse(
            status_code=200,
            content='\n'.join(output)
        )

    def out(self, out_data: dict):
        self.logger.debug(f"Returning data in the format: '{self.out_format}'")
        return getattr(self, f"__format_{self.out_format.replace('-', '_')}__")(out_data)
