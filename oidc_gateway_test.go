package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestGetKeyForTokenMaker(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}

	jwksBytes, _ := json.Marshal(jwks)
	getKeyFunc := getKeyFromJwks(jwksBytes)

	// Test token referencing known key
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)

	token.Header["kid"] = "testKey"

	key, err := getKeyFunc(token)
	if err != nil {
		t.Error(err)
	}
	if key.(*rsa.PublicKey).N.Cmp(pubKey.N) != 0 {
		t.Error("public key does not match")
	}

	// Test token referencing unknown key
	token.Header["kid"] = "unknownKey"
	_, err = getKeyFunc(token)
	if err == nil {
		t.Error("Should fail when passed unknown key")
	}

	// Test token fails with any other signing key than RSA
	tokenHmac := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	_, err = getKeyFunc(tokenHmac)
	if err == nil {
		t.Error("Should fail any signing algorithm other than RSA")
	}
}

func TestValidateTokenCameFromGitHub(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	gatewayContext := &GatewayContext{jwksCache: jwksBytes, jwksLastUpdate: time.Now()}

	// Test token signed in the expected way
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = "testKey"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	claims, err := validateTokenCameFromGitHub(signedToken, gatewayContext)

	if err != nil {
		t.Error(err)
	}
	if claims["for"] != "testing" {
		t.Error("Unable to find claims")
	}

	// Test signing with a unknown key is not allowed
	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signedToken, err = token.SignedString(otherPrivateKey)
	if err != nil {
		panic(err)
	}

	_, err = validateTokenCameFromGitHub(signedToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate token signed with other key")
	}

	// Test unsigned token is not allowed
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodNone, tokenClaims)
	unsignedToken.Header["kid"] = "testKey"

	noneToken, _ := token.SignedString("none signing method allowed")

	_, err = validateTokenCameFromGitHub(noneToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate unsigned token")
	}
}
