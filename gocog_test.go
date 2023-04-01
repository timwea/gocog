package gocog

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var privateKey *rsa.PrivateKey
var jwksString string
var validator CognitoJwtValidator
var payload string
var signedJWT string

type TestTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (t *TestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.RoundTripFunc != nil {
		return t.RoundTripFunc(req)
	}

	return nil, errors.New("RoundTripFunc is nil")
}

func TestMain(m *testing.M) {
	privateKey, jwksString = generateKeys()

	tr := &TestTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(jwksString)),
			}, nil
		},
	}

	http.DefaultTransport = tr

	payload, _ = generateIDTokenPayload()
	signedJWT, _ = generateSignedJWT(privateKey, payload)
	validator = CognitoJwtValidator{UserPoolId: "us-east-1_fakeuserpool", ClientId: "v0axohew6Ejc32mvN1w4BGu4"}

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestCognitoJwtValidator_ValidateIdToken(t *testing.T) {
	err := validator.Validate(signedJWT)
	if err != nil {
		t.Errorf("expected no error but got %v", err)
	}
}

func TestCognitoJwtValidator_ValidateAccessToken(t *testing.T) {
	payload, _ = generateAccessTokenPayload()
	signedJWT, _ = generateSignedJWT(privateKey, payload)
	err := validator.Validate(signedJWT)
	if err != nil {
		t.Errorf("expected no error but got %v", err)
	}
}

func TestCognitoJwtValidator_InvalidJwtString(t *testing.T) {
	err := validator.Validate("")
	expectedErrorMessage := "invalid JWT format"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_InvalidJwtObject(t *testing.T) {
	err := validator.Validate("xxxx.xxxx.xxxx")
	expectedErrorMessage := "error parsing jwt:"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_PublicKeyNotFound(t *testing.T) {
	err := validator.Validate("eyJhbGciOiJSUzI1NiIsICJraWQiOiAiMTIzIn0.eyJ0ZXN0IjoxMjN9.eyJ0ZXN0IjoxMjN9")
	expectedErrorMessage := "public key not found"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_ExpiredToken(t *testing.T) {
	expiredTokenPayload, _ := generateExpiredToken()
	expiredSignedJWT, _ := generateSignedJWT(privateKey, expiredTokenPayload)
	err := validator.Validate(expiredSignedJWT)
	expectedErrorMessage := "error validating jwt: token is expired."
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_InvalidUserPoolId(t *testing.T) {
	validator = CognitoJwtValidator{UserPoolId: "xxxxx", ClientId: "v0axohew6Ejc32mvN1w4BGu4"}
	err := validator.Validate(signedJWT)
	expectedErrorMessage := "invalid Cognito User Pool ID: xxxxx"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_InvalidIssuer(t *testing.T) {
	validator = CognitoJwtValidator{UserPoolId: "us-south-5_fakeuserpool", ClientId: "v0axohew6Ejc32mvN1w4BGu4"}
	err := validator.Validate(signedJWT)
	expectedErrorMessage := "invalid issuer claim"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_InvalidAudience(t *testing.T) {
	validator = CognitoJwtValidator{UserPoolId: "us-east-1_fakeuserpool", ClientId: "xxxx"}
	err := validator.Validate(signedJWT)
	expectedErrorMessage := "invalid audience claim"
	testError(t, err, expectedErrorMessage)
}

func TestCognitoJwtValidator_ModifiedJWT(t *testing.T) {
	validator = CognitoJwtValidator{UserPoolId: "us-east-1_fakeuserpool", ClientId: "v0axohew6Ejc32mvN1w4BGu4"}
	modifiedJWT := modifyJWTString(signedJWT)
	err := validator.Validate(modifiedJWT)
	expectedErrorMessage := "invalid signature"
	testError(t, err, expectedErrorMessage)
}

func testError(t *testing.T, err error, expectedErrorMessage string) {
	if err == nil {
		t.Errorf("Expected error message '%s', but got no error", expectedErrorMessage)
	} else if !strings.Contains(err.Error(), expectedErrorMessage) {
		t.Errorf("Expected error message '%s', but got '%s'", expectedErrorMessage, err.Error())
	}
}

func generateKeys() (*rsa.PrivateKey, string) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privKey.PublicKey

	encodedE := base64.URLEncoding.EncodeToString(intToBytes(pubKey.E))
	encodedE = string(bytes.TrimRight([]byte(encodedE), "="))
	encodedN := base64.URLEncoding.EncodeToString(pubKey.N.Bytes())
	encodedN = string(bytes.TrimRight([]byte(encodedN), "="))

	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"kid": dumbKid(),
				"use": "sig",
				"alg": "RS256",
				"e":   encodedE,
				"n":   encodedN,
			},
		},
	}

	jwksBytes, _ := json.Marshal(jwks)
	jwksStr := string(jwksBytes)

	return privKey, jwksStr

}

func generateSignedJWT(privateKey *rsa.PrivateKey, payload string) (string, error) {
	header := generateJwtHeader()
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))

	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	encodedJWT := encodedHeader + "." + encodedPayload

	hashed := sha256.Sum256([]byte(encodedJWT))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	signedJWT := encodedJWT + "." + encodedSignature

	return signedJWT, nil
}

func generateJwtHeader() string {
	header := map[string]string{
		"alg": "RS256",
		"kid": dumbKid(),
		"typ": "JWT",
	}
	jsonHeader, _ := json.Marshal(header)

	return string(jsonHeader)
}

func generateExpiredToken() (string, error) {
	tokenPayload := map[string]interface{}{
		"exp": int(time.Now().Unix() - 10),
	}
	jsonPayload, _ := json.Marshal(tokenPayload)

	return string(jsonPayload), nil
}

func generateIDTokenPayload() (string, error) {
	tokenPayload := map[string]interface{}{
		"at_hash":          "n1KFZluhgAPirQ_iuSKXMw",
		"sub":              "1e2e7a44-3ca9-4a42-a25b-8ba8a87e71c5",
		"cognito:groups":   []string{"some-group"},
		"email_verified":   false,
		"iss":              "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_fakeuserpool",
		"cognito:username": "Bob.Loblaw",
		"given_name":       "Bob",
		"nonce":            "aUsxbjFQMUFmb1VjOXlpeGVIbkc4eXhQbjRrVkpYamE5Z2xISXQ5LVdPTnZuREFaZTR5ME1HYXhoeUFRN3pYZ3VaUXZmSG13ZDg1cWZ1aG9mbzEzZ1E",
		"origin_jti":       "1c606716-c0b8-4028-9129-1d8792d51dde",
		"aud":              "v0axohew6Ejc32mvN1w4BGu4",
		"event_id":         "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"token_use":        "id",
		"auth_time":        int(time.Now().Unix()),
		"name":             "Bob.Loblaw@BobLoblawLaw.com",
		"exp":              int(time.Now().Unix() + 10),
		"iat":              int(time.Now().Unix()),
		"family_name":      "Loblaw",
		"jti":              "54599eb8-3599-46bd-a6aa-85c7ec2232a0",
		"email":            "Bob.Loblaw@BobLoblawLaw.com",
	}
	jsonPayload, _ := json.Marshal(tokenPayload)

	return string(jsonPayload), nil
}

func generateAccessTokenPayload() (string, error) {
	tokenPayload := map[string]interface{}{
		"sub":            "1e2e7a44-3ca9-4a42-a25b-8ba8a87e71c5",
		"cognito:groups": []string{"some-group"},
		"iss":            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_fakeuserpool",
		"version":        2,
		"client_id":      "v0axohew6Ejc32mvN1w4BGu4",
		"origin_jti":     "1c606716-c0b8-4028-9129-1d8792d51dde",
		"event_id":       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"token_use":      "access",
		"scope":          "some scope",
		"auth_time":      int(time.Now().Unix()),
		"exp":            int(time.Now().Add(time.Minute * 10).Unix()),
		"iat":            int(time.Now().Unix()),
		"jti":            "54599eb8-3599-46bd-a6aa-85c7ec2232a0",
		"username":       "Bob.Loblaw@BobLoblawLaw.com",
	}
	jsonPayload, _ := json.Marshal(tokenPayload)

	return string(jsonPayload), nil
}

func modifyJWTString(str string) string {
	oldStr := strings.Split(str, ".")
	oldStr[2] = badPayload()
	return strings.Join(oldStr, ".")
}

func intToBytes(i int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

func dumbKid() string {
	return "q3nY59yDQ8KfWn+Iit4M4gxZ24DspgTKytWZsaxQncs="
}

func badPayload() string {
	return "t8QivOjwXIvr1t5Qs_EIOD3D8HI5Glxal0ecNOsDV_tYjz0C0L3OqmqoIWl1nkYgjG-dlGb39y_Q1rxA_h_-Ah2xLcapa1aeBH8umeTa-6V_EMiwZaR4Ydz1muOssvIcFzVaeVzfehc7Dvn1pNBRh_U88JTCgX2bH2pRvoRWFH-5DH20iRZdwEJxIGKxMl7i7gjtW_y-HzMXmXETYja-YC3CbmPtjGysS8OxD93pH0vzufcI_act4JzVgKD2EEHtcnskiCz6IgGb7U8T1MOFEUd7UugfPBKRhTfQcJ-jSN5Nuv26BJDAQyjsjNFLVwHz4pTvm9h9wOBwsBW9TtTkEQ"
}
