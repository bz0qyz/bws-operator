import uvicorn
import multiprocessing
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, Depends, Response, Request, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.openapi.utils import get_openapi
from starlette.middleware.base import BaseHTTPMiddleware
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise
from database import TortoiseDB as Database
from database.models import Secret, SecretValue, ApiKey
from helpers import *
from models import HeaderModel, SecretRequest, SecretAcl
from config import Config, Arguments, Logger, TORTOISE_ORM_CONFIG, INIT_LOGS
from bwsclient import BWClient

#####################################################
# Configuration and Logging
#####################################################
config = Config()
config.args = Arguments(
        app_name=config.name,
        app_description=config.description,
        app_version=config.version
    ).args
app_logger = Logger(config.args.log_level)
config.logger = app_logger.logger
config.debug = True if config.args.log_level == 'debug' else False
logger = config.logger
db = Database(
    secret_key=config.args.secret_key,
    no_encrypt=config.args.no_encrypt,
    token_lock_config={
        "token_deny_limit": config.args.token_deny_limit,
        "token_deny_minutes": config.args.token_deny_minutes,
        "token_lock_minutes": config.args.token_lock_minutes
    }
)

logger.info(f"** Starting {config.name} v{config.version} **")
logger.info(f"Log Level: {config.args.log_level}")
logger.info(f"Database Timezone: {config.args.database_timezone}")
if config.debug:
    logger.debug("Debug logging enabled")
if config.args.no_encrypt:
    logger.warning("Data encryption disabled.")
if config.args.token_deny_limit == 0:
    logger.warning("API token auto-lockout disabled.")

# Show log messages generated during initialization (before logging is configured)
for log in INIT_LOGS:
    if "level" not in log:
        log['level'] = 'info'
    getattr(logger, log['level'])(log['message'])


#####################################################
# helper functions
#####################################################
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=config.name,
        version=config.version,
        description=config.description,
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

def validate_headers(x_token: str = Header(...)):
    return HeaderModel(x_token=x_token)

async def load_bws_secret_cache(reload=False):
    # Load the Bitwarden secrets into the database
    # from test_secrets import bws_secrets
    bws_secrets = None
    if not config.client:
        config.client = BWClient(
            api_url=config.args.api_url,
            id_url=config.args.identity_url
            )

    if config.client and config.client.state == config.client.BW_STATE_UNATHENTICATED:
        config.client.authenticate(
            organization_id=config.args.organization_id,
            access_token=config.args.access_token
            )
    if config.client and config.client.state == config.client.BW_STATE_ATHENTICATED:
        bws_secrets = config.client.get_secrets()
    if bws_secrets:
        verb = 'Reloaded' if reload else 'Loaded'
        # Clear the SecretValue cache
        await Secret.all().delete()
        # print(json.dumps(bws_secrets, indent=4))
        await db.load_bws_secrets(bws_secrets)
        logger.info(f"{verb} Bitwarden secrets into the database")
        # Clear the secrets from memory
        bws_secrets = None

def drop_table_sql(dialect: str, table: str):
    if dialect == 'sqlite':
        return f"DROP TABLE IF EXISTS {table};"
    elif dialect == 'mysql':
        return f"SET FOREIGN_KEY_CHECKS = 0; DROP TABLE IF EXISTS {table}; SET FOREIGN_KEY_CHECKS = 1;"
    elif dialect == 'postgres':
        return f"DROP TABLE IF EXISTS {table} CASCADE;"
    else:
        return f"DROP TABLE IF EXISTS {table};"

#####################################################
# FastAPI functions
#####################################################
@asynccontextmanager
async def lifespan(app: FastAPI):
    #####################################################
    # Startup
    #####################################################
    # Add a custom OpenAPI schema
    logger.debug("Adding custom OpenAPI schema")
    app.openapi = custom_openapi

    connection = Tortoise.get_connection("default")
    dialect = connection.capabilities.dialect
    logger.info(f"Resetting Database tables for dialect: {dialect}")
    # Retrieve all table names from the models
    table_names = []
    for app_name, models in Tortoise.apps.items():
        for model_name, model in models.items():
            table_names.append(model._meta.db_table)
    for table in table_names:
        await connection.execute_script(drop_table_sql(dialect, table))

    logger.info("Generating Tortoise ORM schemas....")
    await Tortoise.generate_schemas()
    logger.info("Schema generation complete.")

    # Add a crypto object to the SecretValue model
    SecretValue.set_crypto(db.crypto)
    # Load/Update the Bitwarden secrets into the database
    await load_bws_secret_cache()

    yield
    #####################################################
    # Shutdown
    #####################################################
    logger.info("Shutting down the FastAPI application")
    await Tortoise.close_connections()
    if not config.debug:
        if config.client:
            logger.info("Shutting down the Bitwarden Secrets client")
            config.client.close()


app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def before_request_middleware(request: Request, call_next):
    # Code to run before the request
    user_agent = request.headers.get('User-Agent', 'Unknown')
    # print(f"Request path: {request.url.path}")
    # print(f"UserAgent: {user_agent}")

    # Process the request and get the response
    response = await call_next(request)

    if request.url.path in ['/docs', '/redoc', '/openapi.json', '/api-test']:
        return response

    if not agent_allowed(user_agent, config.args.allowed_user_agent):
        return JSONResponse(
            status_code=404,
            content={"message": "Resource not found."}
        )

    # Code to run after the request
    response.headers['X-Powered-By'] = f"{config.description} v{config.version}"
    response.headers['Server'] = f"{config.name}/{config.version}"
    return response

class EnforceHostHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        allowed_hostnames = [
            f"{config.args.strict_hostname}",
            f"{config.args.strict_hostname}:{config.args.http_port}",
            f"{config.name}",
            f"{config.name}:{config.args.http_port}"
        ]
        # Check the Host header
        host = request.headers.get("host")
        if host not in allowed_hostnames:
            logger.warning(f"Attempt with invalid hostname: '{host}'")
            return JSONResponse(
                status_code=404,
                content={"message": "Resource not found."}
            )

        return await call_next(request)

# Add the middleware to enforce the Host header
if config.args.strict_hostname:
    logger.info(f"Strict hostname enforcing: {config.args.strict_hostname}")
    app.add_middleware(EnforceHostHeaderMiddleware)

#####################################################
# FastAPI Routs
#####################################################
@app.get('/ca-cert')
async def show_ca_cert():
    if not config.args.tls_ca_file:
        return JSONResponse(
            status_code=404,
            content={"message": "Resource Not Found"}
        )
    with open(f"{config.args.tls_ca_file}", "r") as file:
        ca_contents = file.read()  # Read the entire contents of the file

    return PlainTextResponse(ca_contents)

@app.put('/reload-cache')
async def reload_bws_cache(headers: HeaderModel = Depends(validate_headers)):
    await load_bws_secret_cache(reload=True)
    return JSONResponse(
            status_code=200,
            content={"message": "Cache Reloaded"}
        )
@app.post('/secret')
async def get_bitwarden_secret(request: Request, payload: SecretRequest, headers: HeaderModel = Depends(validate_headers)):
    secret_data = None
    all_values = []

    if payload and not (payload.secret_id or payload.project_id):
        return json.dumps({"error": "secret_id or project_id was not found in post data"})

    if payload.secret_id:
        secret_data = await db.get_secret(
            secret_id=payload.secret_id,
            api_token=request.headers.get(f'{config.args.api_token_header}', 'Unset'),
            source_ip=request.client.host,
            debug=config.debug
        )

    if not secret_data:
        return JSONResponse(
            status_code=404,
            content={"message": "Resource Not Found"}
        )

    if isinstance(secret_data, dict):
        logger.debug(f"formatting output in '{payload.output_format.type}' format")
        formatter = ReturnFormat(payload.output_format)
        return formatter.out(secret_data)
    else:
        return secret_data

#####################################################
# MAIN
#####################################################

if __name__ == '__main__':
    # Configure Tortoise ORM
    register_tortoise(
        app,
        config=TORTOISE_ORM_CONFIG,
        generate_schemas=False,  # Schema generation is handled in the lifespan context
        add_exception_handlers=True,  # Add Tortoise-specific exception handlers
    )

    multiprocessing.freeze_support()
    ssl_opts = {}
    if config.args.tls_cert_file and config.args.tls_key_file:
        ssl_opts["ssl_certfile"] = f"{config.args.tls_cert_file}"
        ssl_opts["ssl_keyfile"] = f"{config.args.tls_key_file}"

    if config.args.tls_ca_file:
        ssl_opts["ssl_ca_certs"] = f"{config.args.tls_ca_file}"

    try:
        # Start the HTTP server
        uvicorn.run(
            app, host="0.0.0.0", port=config.args.http_port,
            log_level=config.args.log_level,
            server_header=False,
            **ssl_opts
            )
    except KeyboardInterrupt:
        print("Shutting down the server...")

