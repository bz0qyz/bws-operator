#!/usr/bin/env bash
set -e

if [[ ! -e /etc/pki/cert.pem ]]; then
  echo "[INFO] Generating TLS Certificates with tls-simple"
  /usr/local/bin/tls-simple ca-cert -c ${HOME}/tls-simple.ini
fi

echo "[INFO] starting bws-operator"
echo ${@}
exec ${@}
