# bws-operartor
Bitwarden Secrets Operator API is a lightweight API service that allows you to interact with Bitwarden Secrets in Docker entrypoint scripts.
It is built on top of the Bitwarden SDK and provides a simple REST API to access Bitwarden Secrets in docker.

## Features
- Secure access to Bitwarden Secrets over REST API.
- Access control to Bitwarden Secrets using API keys that limit access to specific secrets and specific source IP addresses.
- Access control lists (ACLs) to restrict access to specific secrets are read from a special Bitwarden secret in yaml format.
- Flexible backend database support for storing secrets in cache. Supports: SQLite, MySQL, PostgreSQL.
- Cached secrets are encrypted using symmetric encryption with a configurable key.
- API keys are stored in the database as a hashed string.
- Secret cache is loaded/refreshed on startup and can be triggered manually using the API.
- Uses a CA-signed certificate for secure communication. The CA public certificate can be obtained using the API and trusted byt the clients.
- Supports running in a Docker container.

## Configuration
The operator is configured using environment variables or command arguments.
The following environment variables are supported:
#### General Configuration:
- `-l`|`--log-level`: Log level (default: INFO). ENV Var: `LOG_LEVEL`
#### Bitwarden Configuration:
- `-t`|`--access-token`: Bitwarden Machine Access Token. ENV Var: `BW_ACCESS_TOKEN`
- `-o`|`--organization-id`: Bitwarden Organization ID. ENV Var: `BW_ORGANIZATION_ID`
- `--api-url`: Bitwarden API URL (default: https://api.bitwarden.com). ENV Var: `BW_API_URL`
- `--identity-url`: Bitwarden Identity URL (default: https://identity.bitwarden.com). ENV Var: `BW_IDENTITY_URL`
#### API Configuration:
- `-p`|`--http-port`: Port to listen on (default: `8080`). ENV Var: `API_HTTP_PORT`
- `--tls-key-file`: TLS Key file (pem format) for the HTTP Server. ENV Var: `API_TLS_KEY_FILE`
- `--tls-cert-file`: TLS Certificate file (pem format) for the HTTP Server. ENV Var: `API_TLS_CERT_FILE`
- `--tls-ca-file`: TLS CA Certificate file (pem format) for the HTTP Server. ENV Var: `API_TLS_CA_CERT_FILE`
#### Database Configuration:
- `--database-url`: Database URL. See [Tortoise ORM Databases](https://tortoise.github.io/databases.html). ENV Var: `DATABASE_URL`
- `--database-timezone`: Database Timezone (default: `UTC`). ENV Var: `DATABASE_TIMEZONE`
- `--no-encrypt true|false`: Disables database encryption (default: `False`. ENV Var: `NO_ENCRYPT`
- `--secret-key`: Cypher Key for database encryption. ENV Var: `SECRET_KEY`
#### Security Configuration
- `--strict-hostname`: Enforces the use of a hostname for the API interface (default: `bws-operator`). ENV Var: `API_STRICT_HOSTNAME`
- `--api-token-header`: Header name for the API Token (default: `x-token`. ENV Var: `API_TOKEN_HEADER`
- `--allowed-user-agent`: Enforce an client userAgent header (default: `bws-operator-client`). ENV Var: `API_ALLOWED_USER_AGENT`
- `--secret-key`: Cypher Key for database encryption. ENV Var: `SECRET_KEY`
##### Token Lockout Configuration
- `--token-deny-limit`: Lockout an API key if it has been denied this many times. a value of 0 disables auto-lock (default: 6). ENV Var: `API_TOKEN_DENY_LIMIT`
- `--token-deny-minutes`: Minutes in history to look for token denies (default: 180). ENV Var: `API_TOKEN_DENY_MINUTES`
- `--token-lock-minutes`: Duration of API token auto-lock (default: 10). ENV Var: `API_TOKEN_LOCK_MINUTES`

### Bitwarden Configuration
The Bitwarden configuration is used to authenticate the operator with the Bitwarden API.
Any projects and/or secrets that are accessed by the operator must be accessible by the machine key.

### API Token ACL Configuration
The API token ACL is stored in a Bitwarden secret in yaml format. 
- The Bitwarden Secret must allow the machine key to read the secret.
- The secret name is `<project_name>_acl` and the content should be in the following format:
```yaml
<api_key>:
    name: <api_key_name>
    enabled: true|false
    secrets:
        - <secret_name>
        - <secret_name>
    sources:
        - <source_ip>
        - <source_ip>
```
#### Example:
```yaml
d9a1374e-53c1-4c73-9b16-92d461a37c7b:
  name: master-key
  enabled: true
  secrets:
    - "*"
  sources:
    - "*"
6c60c1d7-a9f8-443c-7a1a-b9c350525b9d:
  name: key1
  secrets:
     - db1-secret
  sources:
    - 192.168.200.0/24
    - 192.168.0.6
```

### Usage
The operator is designed to be run as a Docker container inside a docker network and accessible only by other containers in the same network.
Containers that need access to the Bitwarden secrets can use an entrypoint script to retrieve the secrets and place the data where needed for the application.

- The operator has a swagger API documentation that can be accessed at `https://<hostname>:<port>/docs` after the operator is running.
- Getting a secret from the operator requires an API key and a secret id. The secret id can also be the name of the secret in Bitwarden.
- The output format can be specified in the request body. The default output format is JSON. See [Output Formats](#output-formats) for more information.

#### Payload
The request body should be a JSON object with the following fields:
- `secret_id`: The secret id or name of the secret in Bitwarden.
- `output_format`: The output format of the secret data. See [Output Formats](#output-formats) for more information.

#### Curl Example:
```bash
curl -sk -X GET --user-agent 'bws-operator-client' \
  -o /tmp/bws-operator-ca.pem \
  https://bws-operator:8080/ca-cert

curl -s -X POST --user-agent 'bws-operator-client' \
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "db1-secret", "output_format": {"type": "ini"}}' \
  -o /tmp/db1-secret.ini \
  https://bws-operator:8080/secret
```

#### Input Formats (Bitwarden Secret Contents)
The operator supports secrets in plain text, json, and yaml formats. 
If the secret contains yaml or json, the operator will parse the data and return the secret data in the requested output format with each key/value pair as secret parts.
The format of the secret data can produce different output formats depending on the structure of the secret data.

#### Output Formats
The operator supports multiple output formats for the secret data. The output format can be specified in the request body.
The following output formats (`type`) are supported:
- `json`: Default output format.
- `env`: Environment variable format. The secret data is formatted as `KEY=VALUE` pairs with an optional `export` prefix.
- `ini`: INI file format which can be formatted in the secret as json with `section` headers. See below for an example.
- `raw`: Raw data format. The secret data is returned as is without any formatting.
- `pyfstr`: Python f-string format. The secret key(s) and value(s) will output as specified in a string argument named: `pyfstr`. See below for an example.

The output format payload  can be specified in the request body as follows:
```json
{
    "output_format": {
        "type": "json",
        "secret_key": true|false, # optional
        "env_export": true|false, # optional 
        "pyfstr": "f'{key} => {value}'" # optional (only used with type: pyfstr) 
    }
}
```
- `secret_key` (`bool`): Include the secret key in the output. In `ini` format, the secret key is the section header unless the secret value contains sections.
- `env_export` (`bool`): Include the `export` prefix in the `env` format.
- `pyfstr` (`string`): A python f-string format string with the variables `{key}` and `{value}`. Example: `f'{key} => {value}'`.

## Full Examples
<hr/>

### Project ACL Secret (demo_acl)
```yaml
6c60c1d7-a9f8-443c-7a1a-b9c350525b9d:
  name: db-token
  secrets:
    - db1-secret
    - db2secret
    - simple-secret
    - txt-secret
  sources:
    - 127.0.0.1
```
<hr/>

### Bitwarden Secret (db1-secret)
```json
{
    "database": {
        "host": "localhost",
        "port": 3306,
        "name": "mydb1",
        "password": "admin123",
        "username": "admin"
    },
    "other": {
        "key1": "value1",
        "key2": "value2"
    }
}
```
#### ini Output Format
```bash
curl -s -X POST --user-agent 'bws-operator-client' \
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "db1-secret", "output_format": {"type": "ini"}}' \
  https://bws-operator:8080/secret
```
response:
```ini
[database]
host = localhost
port = 3306
name = mydb1
password = admin123
username = admin

[other]
key1 = value1
key2 = value2
```
<hr/>

### Bitwarden Secret (db2-secret)
secret value:
```json
{
    "db_host": "localhost",
    "db_port": 3306,
    "db_name": "mydb2",
    "db_password": "admin123",
    "db_username": "admin"
}
```
#### ini Output Format
```bash
curl -s -X POST --user-agent 'bws-operator-client' \
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "db2-secret", "output_format": {"type": "ini"}}' \
  https://bws-operator:8080/secret
```
response:
```ini
[db2-secret]
db_host = localhost
db_port = 3306
db_name = mydb2
db_password = admin123
db_username = admin
````

#### pyfstr Output Format
```bash
curl -s -X POST --user-agent 'bws-operator-client' \
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "db2-secret", "output_format": {"type": "pyfstr", "pyfstr": "{key} || {value}"}}' \
  https://bws-operator:8080/secret
```
response:
```txt
db_host || localhost
db_port || 3306
db_name || mydb2
db_password || admin123
db_username || admin
```
<hr/>

### Bitwarden Secret (simple-secret)
secret value:
```
this-is-a-secure-secret
```

#### env Output Format
```bash
curl -s -X POST --user-agent 'bws-operator-client' \ 
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "simple-secret", "output_format": {"type": "env", "secret_key": false, "env_export": true}}' \
  https://bws-operator:8080/secret
```
response:
```env
export simple-secret='this-is-a-secure-secret'
```
<hr/>

### Bitwarden Secret (txt-secret)
secret value:
```
# DB3 Secret
hostname=localhost
port=3306
name=mydb3
username=admin
password=admin123
```
```bash
curl -s -X POST --user-agent 'bws-operator-client' \
  --cacert /tmp/bws-operator-ca.pem \
  -H "x-token: 6c60c1d7-a9f8-443c-7a1a-b9c350525b9d" \
  -H "Content-type: application/json" \
  -d '{"secret_id": "txt-secret", "output_format": {"type": "raw"}}' \
  https://bws-operator:8080/secret
```
response:
```txt
hostname=localhost
port=3306
name=mydb3
username=admin
password=admin12
```
