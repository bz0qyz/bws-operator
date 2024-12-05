FROM bitnami/python:3.12 AS builder

ARG TLSS_VER=1.0.0
ENV DEBIAN_FRONTEND="noninteractive"

ADD https://github.com/bz0qyz/tls-simple/releases/download/v${TLSS_VER}/tls-simple-linux-amd64.zip /tmp
COPY ./src requirements.txt /usr/local/src
RUN set -ex \
  apt update && apt install -y unzip \
  && unzip /tmp/tls-simple-linux-amd64.zip -d /tmp \
  && cd /usr/local/src \
  && pip3 install --upgrade -r /usr/local/src/requirements.txt \
  && pyinstaller -F --clean -n bws-operator /usr/local/src/main.py \
  && pip3 list


FROM bitnami/python:3.12

LABEL org.opencontainers.image.source=https://github.com/bz0qyz/bws-operator
LABEL org.opencontainers.image.description="Bitwarden Secrets Manager API Operator"
LABEL org.opencontainers.image.licenses=Unlicense

ENV USER=app
ENV USER_ID=1001
ENV PYTHONUNBUFFERED=1
ENV API_HTTP_PORT='8080'
ENV API_TLS_KEY_FILE='/home/app/pki/key.pem'
ENV API_TLS_CERT_FILE='/home/app/pki/cert.pem'
ENV API_TLS_CA_CERT_FILE='/home/app/pki/ca_cert.pem'

COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=builder /usr/local/src/dist/bws-operator /usr/local/bin/bws-operator
COPY --from=builder /tmp/tls-simple /usr/local/bin/tls-simple

RUN set -ex \
  && useradd -m -c "application user" -d /home/${USER} -u ${USER_ID} app

COPY tls-simple.ini /home/app/tls-simple.ini

USER ${USER}
EXPOSE 8080/tcp
WORKDIR /home/app

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/bws-operator"]
