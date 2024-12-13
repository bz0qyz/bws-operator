import os
import sys
import signal
import logging
import json
import ssl
import uvicorn
import multiprocessing
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, Depends, Response, Request, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.openapi.utils import get_openapi
from starlette.middleware.base import BaseHTTPMiddleware
from tortoise.contrib.fastapi import register_tortoise
from tortoise.queryset import Q
from database import TortoiseDB as Database
from database.models import Secret, SecretValue, ApiKey
from helpers import *
from models import HeaderModel, SecretRequest, SecretAcl
from config import Config, Arguments, Logger, TORTOISE_ORM_CONFIG
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
db = Database(config.args.secret_key, config.args.no_encrypt)

logger.info(f"** Starting {config.name} v{config.version} **")
if config.debug:
    logger.debug("Debug logging enabled")

# if not config.client:
#     config.client = BWClient(
#         api_url=config.args.api_url,
#         id_url=config.args.identity_url
#         )
#
# if config.client and config.client.state == config.client.BW_STATE_UNATHENTICATED:
#     config.client.authenticate(
#         organization_id=config.args.organization_id,
#         access_token=config.args.access_token
#         )
# if config.client and config.client.state == config.client.BW_STATE_ATHENTICATED:
#     bws_secrets = config.client.get_secrets()





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
    from test_secrets import bws_secrets
    if bws_secrets:
        verb = 'Reloaded' if reload else 'Loaded'
        # print(json.dumps(bws_secrets, indent=4))
        await db.load_bws_secrets(bws_secrets)
        logger.info(f"{verb} Bitwarden secrets into the database")
        # Clear the secrets from memory
        bws_secrets = None

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

    # Add a crypto object to the SecretValue model
    SecretValue.set_crypto(db.crypto)
    # Load the Bitwarden secrets into the database
    await load_bws_secret_cache()


    yield
    #####################################################
    # Shutdown
    #####################################################
    logger.info("Shutting down the FastAPI application")
    if not config.debug:
        if config.client:
            logger.info("Shutting down the Bitwarden Secret Cache")
            config.client.close()


app = FastAPI(lifespan=lifespan)
# app = FastAPI()

@app.middleware("http")
async def before_request_middleware(request: Request, call_next):
    # Code to run before the request
    user_agent = request.headers.get('User-Agent', 'Unknown')
    remote_ip = request.client.host
    token = request.headers.get(f'{config.args.api_token_header}', 'Unset')
    # print(f"Request path: {request.url.path}")
    # print(f"Remote IP: {remote_ip}")
    # print(f"API Token: {token}")
    # print(f"UserAgent: {user_agent}")

    # Process the request and get the response
    response = await call_next(request)

    if request.url.path in ['/docs', '/redoc', '/openapi.json', '/api-test']:
        return response

    # if (not valid_token(token, config.args.api_token) or
    #       not agent_allowed(user_agent, config.args.allowed_user_agent) or
    #       not ip_allowed(remote_ip, config.args.allowed_cidrs)
    #     ):
    #     return JSONResponse(
    #         status_code=404,
    #         content={"message": "Resource not found."}
    #     )

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
async def get_bitwarden_secret(payload: SecretRequest, headers: HeaderModel = Depends(validate_headers)):
    secret_data = None
    all_values = []

    if payload and not (payload.secret_id or payload.project_id):
        return json.dumps({"error": "secret_id or project_id was not found in post data"})

    if payload.secret_id:
        # secret_data = await Secret.get(bw_secret_id=payload.secret_id).all()
        secret_data = await Secret.filter(
            Q(bw_secret_id=payload.secret_id) | Q(key=payload.secret_id)
        ).first()
        await secret_data.fetch_related("values")

        for value in secret_data.values:
            print(f"{value.key}: {value.decrypted_value}")
            all_values.append(value.as_dict)
        if secret_data and hasattr(secret_data, "values"):
            # all_values[secret_data.key] = secret_data.values
            return JSONResponse(all_values)
    # elif payload.project_id:
    #     secret_data = config.client.get_project_secrets(project_id=payload.project_id)
    #     for secret in secret_data:
    #         if hasattr(secret, "values"):
    #             all_values[secret.key] = secret.values
    #
    # if len(all_values) > 0:
    #     # Return a response
    #     formatter = ReturnFormat(payload.output_format)
    #     print(formatter.content_type['type'])
    #
    #     if formatter.content_type['type'] == 'text/plain':
    #         return PlainTextResponse(formatter.out(all_values))
    #     if formatter.content_type['type'] == 'application/json':
    #         return JSONResponse(all_values)
    #     else:
    #         return formatter.out(all_values)
    # else:
    #     return JSONResponse(
    #         status_code=404,
    #         content={"message": "Resource not found."}
    #     )


@app.put('/acl')
async def set_secret_acl(payload: SecretAcl, headers: HeaderModel = Depends(validate_headers)):
    if not hasattr(payload, "token") :
        return json.dumps({"error": "token was not found in post data"})
    if len(payload.token.strip()) < 16:
        return json.dumps({"error": "token is too short. Must be at least 16 characters."})
    return await db.insert_acl(payload)

@app.get('/acl')
async def get_api_keys():
    ApiKey.set_crypto(db.crypto)
    try:
        api_key = ApiKey(token="test_key_only", a_value=f"{os.urandom(8)}")
        await api_key.update_or_create()
    except Exception as e:
        logger.debug(f"Error: {e}")
    api_keys = await ApiKey.all()
    return_value = {}
    for key in api_keys:
        logger.debug(f"Key: {key.decrypted_token}")
        return_value[key.id] = {"token": key.decrypted_token, "a_value": key.a_value}
    return return_value
#####################################################
# MAIN
#####################################################

if __name__ == '__main__':
    # Configure Tortoise ORM
    register_tortoise(
        app,
        config=TORTOISE_ORM_CONFIG,
        generate_schemas=True,  # Automatically generate schema on first run
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

