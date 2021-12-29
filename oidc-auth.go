// curl --unix-socket /tmp/oidc-auth.socket http://test
// https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c

package main

import (
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "math/big"
    "net"
    "net/http"
    "os"
    "strings"

    "github.com/golang-jwt/jwt"
)

type JWK struct {
    n string
    kty string
    kid string
    alg string
    e string
    use string
    x5c []string
    x5t string
}

type JWKS struct {
    keys []JWK
}

func getKeyForToken(token *jwt.Token) (interface{}, error) {
    // https://github.com/golang-jwt/jwt
    if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }

    resp, err := http.Get("https://token.actions.githubusercontent.com/.well-known/jwks")
    if err != nil {
        return nil, fmt.Errorf("Unable to get JWKS configuration")
    }

    jwksString, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("Unable to get JWKS configuration")
    }

    // https://gobyexample.com/json
    var jwks JWKS
    if err = json.Unmarshal(jwksString, &jwks); err != nil {
        return nil, fmt.Errorf("Unable to parse JWKS")
    }

    for _, jwk := range jwks.keys {
        if jwk.kid == token.Header["kid"] {
            // TODO: should we do something with x5c / x5t?

            // https://github.com/lestrrat-go/jwx/blob/main/jwk/jwk.go
            // https://pkg.go.dev/crypto/rsa#PublicKey
            nBytes, err := base64.RawURLEncoding.DecodeString(jwk.n)
            if err != nil {
                return nil, fmt.Errorf("Unable to parse key")
            }
            var n big.Int

            eBytes, err := base64.RawURLEncoding.DecodeString(jwk.e)
            if err != nil {
                return nil, fmt.Errorf("Unable to parse key")
            }
            var e big.Int

            key := rsa.PublicKey {
                N: n.SetBytes(nBytes),
                E: int(e.SetBytes(eBytes).Uint64()),
            }

            return key, nil
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

    fmt.Println("In handler")
    authorizationHeader := req.Header.Get("Authorization")

    if !strings.HasPrefix(authorizationHeader, "Basic ") {
        fmt.Println("Authorization header malformed")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    userPass, err := base64.StdEncoding.DecodeString(authorizationHeader[len("Basic "):])
    if err != nil {
        fmt.Println("Authorization header malformed")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    if !strings.Contains(string(userPass), ":") {
        fmt.Println("Authorization header malformed")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    pass := strings.Split(string(userPass), ":")[1]

    oidcTokenString, err := base64.StdEncoding.DecodeString(pass)
    if err != nil {
        fmt.Println("Authorization information malformed")
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    oidcToken, err := jwt.Parse(string(oidcTokenString), getKeyForToken)
    if err != nil {
        fmt.Println(err)
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }

    fmt.Println(oidcToken.Claims)

    // TODO: check claims in token per https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token

    // TODO: do the proxying here

    w.Write([]byte("OK"))
}

func main() {
    fmt.Println("starting up")
    os.Remove("/tmp/oidc-auth.socket")

    server := http.Server{
        Handler: http.HandlerFunc(handler),
    }

    unixListener, err := net.Listen("unix", "/tmp/oidc-auth.socket")
    if err != nil {
        panic(err)
    }

    err = os.Chown("/tmp/oidc-auth.socket", 101, 101)

    server.Serve(unixListener)
}
