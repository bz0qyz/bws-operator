import os
import sys
import argparse
import logging
import ipaddress

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
    version = "1.0.0"
    client = None
    args = None
    logger = None
    debug = False

class Arguments:
    DEFAULT_API_URL = "https://api.bitwarden.com"
    DEFAULT_IDENTITY_URL = "https://identity.bitwarden.com"
    DEFAULT_ALLOWED_CIDRS = "172.17.0.0/16"
    DEFAULT_API_HTTP_PORT = 6666

    def __init__(self, app_name: str, app_version: str, app_description: str):
        parser = argparse.ArgumentParser(description=app_description, prog=f"{app_name} {app_version}")
        parser.add_argument('-l', '--log-level', required=False,
            help=f'Log level: {", ".join(LOG_LEVEL.keys())}. ENV Var: LOG_LEVEL',
            choices=LOG_LEVEL.keys(), default='info', metavar='info',
            action=EnvDefault, envvar="LOG_LEVEL"
        )
        parser.add_argument(
            '-t', '--access_token', required=True,
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
        parser.add_argument(
            '--allowed-cidrs', required=False,
            help='Enforce API Allowed CIDRs (comma seperated). ENV Var: API_ALLOWED_CIDRS',
            default=self.DEFAULT_ALLOWED_CIDRS, metavar="'192.168.0.0/24, 172.21.254.0/24'",
            action=EnvDefault, envvar="API_ALLOWED_CIDRS"
        )
        parser.add_argument(
            '--api-token', required=True,
            help='Enforce an API token header. Multiple allowed (comma seperated). ENV Var: API_TOKEN',
            default=None, metavar='long-obscure-string-or-uuid',
            action=EnvDefault, envvar="API_TOKEN"
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
            '-p', '--http-port', required=False,
            help='Port to listen on for the HTTP Server. ENV Var: API_HTTP_PORT',
            type=int, default=self.DEFAULT_API_HTTP_PORT, metavar=self.DEFAULT_API_HTTP_PORT,
            action=EnvDefault, envvar="API_HTTP_PORT"
        )
        parser.add_argument(
            '--tls-key-file', required=False,
            help='TLS Key file (pem format) for the HTTP Server. ENV Var: API_HTTP_PORT',
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
        parser.add_argument(
            '--strict-hostname', required=False,
            help='Enforces the use of a hostname for the API interface. ENV Var: API_STRICT_HOSTNAME',
            default=None, metavar=f"{app_name}",
            action=EnvDefault, envvar="API_STRICT_HOSTNAME"
        )
        self.args = parser.parse_args()

        # Make the allowed CIDRs a list and verify that they are actial CIDRs
        allowed_cidrs = [cidr.strip() for cidr in self.args.allowed_cidrs.split(',')]
        self.args.allowed_cidrs = self.validate_cidrs(cidrs=allowed_cidrs)

        # Make the API token a list
        self.args.api_token = [token.strip() for token in self.args.api_token.split(',')]

    def __repr__(self):
        return self.args

    def validate_cidrs(self, cidrs: list):
        valid_cidrs = []
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)  # Validate CIDR
                valid_cidrs.append(cidr)
            except ValueError:
                print(f"[WARNING] Invalid CIDR: '{cidr}'. Ommitting it.")
        return valid_cidrs


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

    def __repr__(self):
        return self.logger
