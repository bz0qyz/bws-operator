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
from helpers import *
from models import HeaderModel, SecretRequest
from config import Config, Arguments, Logger
from bwclient import BWClient

#####################################################
# Configuration and Logging
#####################################################
config = Config()
config.args = Arguments(
        app_name = config.name,
        app_description = config.description,
        app_version = config.version
    ).args
app_logger = Logger(config.args.log_level)
config.logger = app_logger.logger
config.debug = True if config.args.log_level == 'debug' else False

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
if config.client and not config.client.state == config.client.BW_STATE_CACHE_READY:
    config.client.load_cache()

logger = config.logger
# print(f"STATE: {config.client.state}")

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

    yield
    #####################################################
    # Shutdown
    #####################################################
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

    if request.url.path in ['/docs', '/redoc', '/openapi.json']:
        return response

    if (not valid_token(token, config.args.api_token) or 
          not agent_allowed(user_agent, config.args.allowed_user_agent) or
          not ip_allowed(remote_ip, config.args.allowed_cidrs)
        ):
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
@app.options('/ca-cert')
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
    config.client.load_cache(reload=True)
    return JSONResponse(
            status_code=200,
            content={"message": "Cache Reloaded", "State": f"{config.client.state}"}
        )
@app.post('/secret')
async def get_bitwarden_secret(payload: SecretRequest, headers: HeaderModel = Depends(validate_headers)):
    secret_data = None
    all_values = {}

    if payload and not (payload.secret_id or payload.project_id):
        return json.dumps({"error": "secret_id or project_id was not found in post data"})

    if payload.secret_id:
        secret_data = config.client.get_secret(secret_id=payload.secret_id)
        if secret_data and hasattr(secret_data, "values"):
            all_values[secret_data.key] = secret_data.values
    elif payload.project_id:
        secret_data = config.client.get_project_secrets(project_id=payload.project_id)
        for secret in secret_data:
            if hasattr(secret, "values"):
                all_values[secret.key] = secret.values

    if len(all_values) > 0:
        # Return a response
        formatter = ReturnFormat(payload.output_format)
        print(formatter.content_type['type'])

        if formatter.content_type['type'] == 'text/plain':
            return PlainTextResponse(formatter.out(all_values))
        if formatter.content_type['type'] == 'application/json':
            return JSONResponse(all_values)
        else:
            return formatter.out(all_values)
    else:
        return JSONResponse(
            status_code=404,
            content={"message": "Resource not found."}
        )

#####################################################
# MAIN
#####################################################  
if __name__ == '__main__':
    multiprocessing.freeze_support()
    ssl_opts = {}
    if config.args.tls_cert_file and config.args.tls_key_file:
        ssl_opts["ssl_certfile"] = f"{config.args.tls_cert_file}"
        ssl_opts["ssl_keyfile"] = f"{config.args.tls_key_file}"
        
    if config.args.tls_ca_file:
        ssl_opts["ssl_ca_certs"] = f"{config.args.tls_ca_file}"

    try:
        # Start the HTTP server 
        print(f"Debug?: {config.debug}")
        uvicorn.run(
            app, host="0.0.0.0", port=config.args.http_port,
            log_level=config.args.log_level,
            server_header=False,
            **ssl_opts
            )
    except KeyboardInterrupt:
        print("Shutting down the server...")

