import os
import sys
import argparse
import logging
from zoneinfo import ZoneInfo
from database import models

INIT_LOGS = []
TORTOISE_ORM_CONFIG = {
    "connections": {
        "default": "sqlite://db.sqlite3"
    },
    "apps": {
        "models": {
            "models": [models],
            "default_connection": "default",
        },
    },
    "use_tz": True,  # Use timezone-aware datetimes
    "timezone": f"utc",  # Set the timezone
}

LOG_FORMAT = {
    "std_format": logging.Formatter(
        f'%(asctime)s %(levelname)-8s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'),
    "debug_format": logging.Formatter(
        f'%(asctime)s %(levelname)-8s:%(message)s (%(filename)s: %(lineno)d)',
        datefmt='%Y-%m-%d %H:%M:%S')
    }
LOG_LEVEL = {
    "critical": {"level": logging.CRITICAL, "format": LOG_FORMAT["std_format"]},
    "error": {"level": logging.ERROR, "format": LOG_FORMAT["std_format"]},
    "warning": {"level": logging.WARNING, "format": LOG_FORMAT["std_format"]},
    "info": {"level": logging.INFO, "format": LOG_FORMAT["std_format"]},
    "debug": {"level": logging.DEBUG, "format": LOG_FORMAT["debug_format"]},
    }

class Config:
    name = "bws-operator"
    description = "Bitwarden Secrets Operator"
    version = "0.1.0"
    client = None
    args = None
    logger = None
    debug = False

class Arguments:
    DEFAULT_API_URL = "https://api.bitwarden.com"
    DEFAULT_IDENTITY_URL = "https://identity.bitwarden.com"
    DEFAULT_API_HTTP_PORT = 8080
    DEFAULT_DATABASE_URL = "sqlite://db.sqlite3"
    DEFAULT_DATABASE_TIMEZONE = "UTC"

    def __init__(self, app_name: str, app_version: str, app_description: str):
        parser = argparse.ArgumentParser(description=app_description, prog=f"{app_name} {app_version}")
        # General Arguments
        parser.add_argument('-l', '--log-level', required=False,
            help=f'Log level: {", ".join(LOG_LEVEL.keys())}. ENV Var: LOG_LEVEL',
            choices=LOG_LEVEL.keys(), default='info', metavar='info',
            action=EnvDefault, envvar="LOG_LEVEL"
        )
        # Bitwarden Arguments
        parser.add_argument(
            '-t', '--access-token', required=True,
            help='Bitwarden Machine Access Token. ENV Var: BW_ACCESS_TOKEN',
            action=EnvDefault, envvar="BW_ACCESS_TOKEN"
        )
        parser.add_argument(
            '-o', '--organization-id', required=True,
            help='Bitwarden Organization ID. ENV Var: BW_ORGANIZATION_ID',
            action=EnvDefault, envvar="BW_ORGANIZATION_ID"
        )
        parser.add_argument(
            '--api-url', required=False,
            help='Bitwarden API URL. ENV Var: BW_API_URL',
            default=self.DEFAULT_API_URL, metavar=self.DEFAULT_API_URL,
            action=EnvDefault, envvar="BW_API_URL"
        )
        parser.add_argument(
            '--identity-url', required=False,
            help='Bitwarden Identity URL. ENV Var: BW_IDENTITY_URL',
            default=self.DEFAULT_IDENTITY_URL, metavar=self.DEFAULT_IDENTITY_URL,
            action=EnvDefault, envvar="BW_IDENTITY_URL"
        )
        # API Server Arguments
        parser.add_argument(
            '-p', '--http-port', required=False,
            help='Port to listen on for the HTTP Server. ENV Var: API_HTTP_PORT',
            type=int, default=self.DEFAULT_API_HTTP_PORT, metavar=self.DEFAULT_API_HTTP_PORT,
            action=EnvDefault, envvar="API_HTTP_PORT"
        )
        parser.add_argument(
            '--tls-key-file', required=False,
            help='TLS Key file (pem format) for the HTTP Server. ENV Var: API_TLS_KEY_FILE',
            default=None, metavar=f"/path/to/key/file.pem",
            action=EnvDefault, envvar="API_TLS_KEY_FILE"
        )
        parser.add_argument(
            '--tls-cert-file', required=False,
            help='TLS Certificate file (pem format) for the HTTP Server. ENV Var: API_TLS_CERT_FILE',
            default=None, metavar=f"/path/to/cert/file.pem",
            action=EnvDefault, envvar="API_TLS_CERT_FILE"
        )
        parser.add_argument(
            '--tls-ca-file', required=False,
            help='TLS CA Certificate file (pem format) for the HTTP Server. ENV Var: API_TLS_CA_CERT_FILE',
            default=None, metavar=f"/path/to/cert/ca.pem",
            action=EnvDefault, envvar="API_TLS_CA_CERT_FILE"
        )
        # API Security Arguments
        parser.add_argument(
            '--strict-hostname', required=False,
            help='Enforces the use of a hostname for the API interface. ENV Var: API_STRICT_HOSTNAME',
            default=None, metavar=f"{app_name}",
            action=EnvDefault, envvar="API_STRICT_HOSTNAME"
        )
        parser.add_argument(
            '--api-token-header', required=False,
            help='Header name for the API Token. ENV Var: API_TOKEN_HEADER',
            default='X-Token', metavar='X-Token',
            action=EnvDefault, envvar="API_TOKEN_HEADER"
        )
        parser.add_argument(
            '--allowed-user-agent', required=False,
            help='Enforce an client userAgent header. ENV Var: API_ALLOWED_USER_AGENT',
            default=f"{app_name}-client", metavar=f"{app_name}-client",
            action=EnvDefault, envvar="API_ALLOWED_USER_AGENT"
        )
        parser.add_argument(
            '--token-deny-limit', required=False,
            help='Auto-lock an API key if it has been denied this many times. a value of 0 disables auto-lock. ENV Var: API_TOKEN_DENY_LIMIT',
            type=int, default=6, metavar=6,
            action=EnvDefault, envvar="API_TOKEN_DENY_LIMIT"
        )
        parser.add_argument(
            '--token-deny-minutes', required=False,
            help='Minutes in history to look for token denies. ENV Var: API_TOKEN_DENY_MINUTES',
            type=int, default=180, metavar=180,
            action=EnvDefault, envvar="API_TOKEN_DENY_MINUTES"
        )
        parser.add_argument(
            '--token-lock-minutes', required=False,
            help='Duration of API token auto-lock. ENV Var: API_TOKEN_LOCK_MINUTES',
            type=int, default=10, metavar=10,
            action=EnvDefault, envvar="API_TOKEN_LOCK_MINUTES"
        )
        # Database Arguments
        parser.add_argument(
            '--database-url', required=False,
            help='Database URL. See https://tortoise.github.io/databases.html. ENV Var: DATABASE_URL',
            default=self.DEFAULT_DATABASE_URL, metavar=self.DEFAULT_DATABASE_URL,
            action=EnvDefault, envvar="DATABASE_URL"
        )
        parser.add_argument(
            '--database-timezone', required=False,
            help='Database URL. See https://tortoise.github.io/databases.html. ENV Var: DATABASE_URL',
            default=self.DEFAULT_DATABASE_TIMEZONE, metavar=self.DEFAULT_DATABASE_TIMEZONE,
            action=EnvDefault, envvar="DATABASE_TIMEZONE"
        )
        parser.add_argument(
            '--secret-key', required=False,
            help='Cypher Key for database encryption. ENV Var: SECRET_KEY',
            default=None, metavar=f"long_and_strong_key",
            action=EnvDefault, envvar="SECRET_KEY"
        )
        parser.add_argument(
            '--no-encrypt', required=False,
            help='Disables database encryption. ENV Var: NO_ENCRYPT',
            default=False, metavar=f"False",
            type=bool, action=EnvDefault, envvar="NO_ENCRYPT"
        )

        self.args = parser.parse_args()

        # Verify the timezone is valid
        if not self.is_valid_timezone(self.args.database_timezone):
            INIT_LOGS.append(
                {"level": "warning", "message": f"Invalid timezone requested: '{self.args.database_timezone}'"})
            INIT_LOGS.append(
                {"level": "info", "message": f"Valid Timezones: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"})
            INIT_LOGS.append(
                {"level": "info", "message": f"Falling back to the default timezone: '{self.DEFAULT_DATABASE_TIMEZONE}'"})

            self.args.database_timezone = self.DEFAULT_DATABASE_TIMEZONE

        # Set the database connection and timezone
        TORTOISE_ORM_CONFIG["connections"]["default"] = self.args.database_url
        TORTOISE_ORM_CONFIG["timezone"] = self.args.database_timezone


    def __repr__(self):
        return self.args

    def is_valid_timezone(self, tz_name):
        try:
            ZoneInfo(tz_name)
            return True
        except Exception as e:
            return False


class EnvDefault(argparse.Action):
    """ Argparse Action that uses ENV Vars for default values """

    def boolify(self, s):
        if isinstance(s, bool):
            return s
        if s.lower() in ['true', 't', 'yes', 'y', '1']:
            return True
        if s.lower() in ['false', 'f', 'no', 'n', '0']:
            return False
        return s

    def __init__(self, envvar, required=False, default=None, **kwargs):
        if envvar and envvar in os.environ:
            default = self.boolify(os.environ[envvar])
            required = False

        super().__init__(default=default,
                         required=required,
                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


class Logger:
    def __init__(self, log_level):
        if log_level not in LOG_LEVEL.keys():
            log_level = 'info'

        self.debug = True if log_level == 'debug' else False
        # create the logger
        self.logger = logging.getLogger()
        self.logger.setLevel(LOG_LEVEL[log_level]["level"])
        # initialize the console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(LOG_LEVEL[log_level]["format"])
        self.logger.addHandler(console_handler)

        # Set specific logging for Tortoise ORM
        tortoise_logger = logging.getLogger("tortoise")
        tortoise_logger.setLevel(logging.WARNING)
        tortoise_logger.addHandler(console_handler)

        # Set specific logging for aiosqlite
        aiosqlite_logger = logging.getLogger("aiosqlite")
        aiosqlite_logger.setLevel(logging.WARNING)
        aiosqlite_logger.addHandler(console_handler)

        # Set specific logging for aiomysql
        aiomysql_logger = logging.getLogger("aiomysql")
        aiomysql_logger.setLevel(logging.WARNING)
        aiomysql_logger.addHandler(console_handler)


    def __repr__(self):
        return self.logger
