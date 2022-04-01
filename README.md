# actions-oidc-proxy-example

Have you ever wanted to connect to a private network from a GitHub-hosted Actions runner?

This gateway is designed to be an internet-facing gateway for proxying network traffic into a private network, authorized by the OIDC token in Actions:

```

    GitHub Actions   |                     |       Private Network
                     |                     |
     ----------      |   Actions      --------------       -----------------
    |  Runner  | ----|-- OIDC    --> | This Gateway |---> | Private Service |
     ----------      |   Token        --------------       -----------------
                     |                     |

```

## Major caveats

🚨🚨 This is not yet ready for production systems! 🚨🚨

- Parsing JWTs is a [notorious source of security bugs](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/); at a minimum this should undergo some sort of application security review

- You'd probably want to use a real TLS certificate for the proxy (or distribute the self-signed certificate for use in the Action)

- This was thrown together as a proof-of-concept, and probably doesn't scale very well

- It should maybe support more features, like proxying beyond HTTP CONNECT, or allowlisting outbound domains

- Users would need to customize this so the gateway only accepts their OIDC tokens, and not OIDC tokens from any Actions runner. This example is scoped to workflows in the private repo https://github.com/steiza/actions_testing, but the OIDC token means you could scope up to a whole org, or down to a specific workflow.

- Users would be responsible for deploying the gateway with scoped access to their private network

## How would I configure this?

At a minimum, you probably want to modify the hard-coded `if claims["repository"] != "steiza/actions_testing"` check in `oidc-auth.go`.

## How would I deploy this?

These are rough deploy notes that you'd have to customize for your use case:

```
# Generate self-signed TLS certificate
$ openssl req -new -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out cert.pem -keyout key.pem

# Build container and upload to registry
$ GOOS=linux go build oidc-auth.go
$ docker build . -t actions-oidc-proxy
$ echo $DOCKER_PAT | docker login ghcr.io -u steiza --password-stdin
$ docker tag actions-oidc-proxy ghcr.io/steiza/actions-oidc-proxy:v1
$ docker push ghcr.io/steiza/actions-oidc-proxy:v1

# Deploy to Azure
$ az group create --name "ProxyResourceGroup" --location eastus
$ az monitor log-analytics workspace create --resource-group ProxyResourceGroup --workspace-name ProxyLogs
$ LOG_ANALYTICS_WORKSPACE_CLIENT_ID=`az monitor log-analytics workspace show --query customerId -g ProxyResourceGroup -n ProxyLogs -o tsv | tr -d '[:space:]'`
$ LOG_ANALYTICS_WORKSPACE_CLIENT_SECRET=`az monitor log-analytics workspace get-shared-keys --query primarySharedKey -g ProxyResourceGroup -n ProxyLogs -o tsv | tr -d '[:space:]'`
$ az container create --resource-group ProxyResourceGroup --name proxy-container --image ghcr.io/steiza/actions-oidc-proxy:v1 --registry-login-server ghcr.io --registry-username steiza --registry-password $PACKAGES_RO_PAT --log-analytics-workspace $LOG_ANALYTICS_WORKSPACE_CLIENT_ID --log-analytics-workspace-key $LOG_ANALYTICS_WORKSPACE_CLIENT_SECRET --dns-name-label oidc-proxy-test --ports 8443
```

## How would I use this?

You could set up an Action to use this with something like:

```
...

jobs:
  your_job_name:
    ...
    permissions:
      id-token: write
    steps:
      ...

      - name: Get OIDC token
        run: |
          curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" -H "Accept: application/json; api-version=2.0" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://ActionsOIDCGateway" | jq -r ".value" > token.txt

      - name: Example using gateway as a proxy
        run: |
          curl -v --proxy-insecure -p --proxy-header "Gateway-Authorization: $(cat token.txt)" -x https://oidc-proxy-test.eastus.azurecontainer.io:8443 https://www.google.com

      - name: Example of an API gateway
        run: |
          curl -v --insecure -H "Gateway-Authorization: $(cat token.txt)" https://oidc-proxy-test.eastus.azurecontainer.io:8443/apiExample

    ...
```
