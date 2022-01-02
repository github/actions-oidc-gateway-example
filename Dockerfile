FROM ubuntu:20.04

RUN apt update && apt install -y ca-certificates

COPY oidc-auth /usr/local/bin/
COPY key.pem cert.pem /etc/

EXPOSE 8443

CMD ["/usr/local/bin/oidc-auth"]
