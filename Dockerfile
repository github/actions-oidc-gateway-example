FROM nginx:1.21

COPY nginx.conf /etc/nginx/nginx.conf
COPY hello.html /usr/share/nginx/proxy/
COPY oidc-auth  /usr/local/bin/

CMD ["sh", "-c", "nginx ; /usr/local/bin/oidc-auth"]
