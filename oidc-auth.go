package main

import (
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "math/big"
    "net"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt"
)

type JWK struct {
    N string
    Kty string
    Kid string
    Alg string
    E string
    Use string
    X5c []string
    X5t string
}

type JWKS struct {
    Keys []JWK
}

func getKeyForToken(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    resp, err := http.Get("https://token.actions.githubusercontent.com/.well-known/jwks")
    if err != nil {
        fmt.Println(err)
        return nil, fmt.Errorf("Unable to get JWKS configuration")
    }

    jwksString, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println(err)
        return nil, fmt.Errorf("Unable to get JWKS configuration")
    }

    var jwks JWKS
    if err = json.Unmarshal(jwksString, &jwks); err != nil {
        return nil, fmt.Errorf("Unable to parse JWKS")
    }

    for _, jwk := range jwks.Keys {
        if jwk.Kid == token.Header["kid"] {
            nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
            if err != nil {
                return nil, fmt.Errorf("Unable to parse key")
            }
            var n big.Int

            eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
            if err != nil {
                return nil, fmt.Errorf("Unable to parse key")
            }
            var e big.Int

            key := rsa.PublicKey {
                N: n.SetBytes(nBytes),
                E: int(e.SetBytes(eBytes).Uint64()),
            }

            return &key, nil
        }
    }

    return nil, fmt.Errorf("Unknown kid: %v", token.Header["kid"])
}

func handler(w http.ResponseWriter, req *http.Request) {
    if req.Method != http.MethodConnect {
        fmt.Println("Non-connect request")
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    oidcTokenString := req.Header.Get("Proxy-Authorization")

    oidcToken, err := jwt.Parse(string(oidcTokenString), getKeyForToken)
    if err != nil || !oidcToken.Valid {
        fmt.Println("Unable to validate JWT")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    claims, ok := oidcToken.Claims.(jwt.MapClaims)
    if !ok {
        fmt.Println("Unable to map JWT claims")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    // NOTE: you *must* add conditions that filter incoming requests, so that
    // untrusted repositories or workflows can’t access your resources
    //
    // See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud
    if claims["repository"] != "steiza/actions_testing" {
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    proxyConn, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
    if err != nil {
        fmt.Println(err)
        http.Error(w, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
        return
    }

    w.WriteHeader(http.StatusOK)

    hijacker, ok := w.(http.Hijacker)
    if !ok {
        fmt.Println("Connection hijacking not supported")
        http.Error(w, http.StatusText(http.StatusExpectationFailed), http.StatusExpectationFailed)
        return
    }

    reqConn, _, err := hijacker.Hijack()
    if err != nil {
        fmt.Println(err)
        http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
        return
    }

    go transfer(proxyConn, reqConn)
    go transfer(reqConn, proxyConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
    defer destination.Close()
    defer source.Close()
    io.Copy(destination, source)
}

func main() {
    fmt.Println("starting up")

    server := http.Server{
        Addr: ":8443",
        Handler: http.HandlerFunc(handler),
        ReadTimeout: 60 * time.Second,
        WriteTimeout: 60 * time.Second,
    }

    server.ListenAndServeTLS("/etc/cert.pem", "/etc/key.pem")
}
