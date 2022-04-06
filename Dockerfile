FROM ubuntu:20.04

RUN apt update && apt install -y ca-certificates

COPY oidc_gateway /usr/local/bin/
COPY key.pem cert.pem /etc/

EXPOSE 8000

CMD ["/usr/local/bin/oidc_gateway"]
