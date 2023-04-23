package gocog

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type DeconstructedToken struct {
	Header       map[string]interface{}
	Payload      map[string]interface{}
	B64Header    string
	B64Payload   string
	B64Signature string
	B64Token     string
}

// CognitoJwtValidator is a struct that represents an Amazon Cognito JWT validator.
type CognitoJwtValidator struct {
	UserPoolId string // UserPoolId is the ID of the Amazon Cognito user pool.
	ClientId   string // ClientId is the ID of the Amazon Cognito app client.
}

type JsonWebKeyAPI interface {
	GetJsonWebKeySet(url string) (map[string]interface{}, error)
}

type JwksClient struct {
	httpClient *http.Client
}

func b64Decode(b64Str string) (string, error) {
	padding := strings.Repeat("=", (4-len(b64Str)%4)%4)
	b64Str += padding
	decoded, err := base64.URLEncoding.DecodeString(b64Str)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func (client *JwksClient) GetJsonWebKeySet(url string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	var jwks map[string]interface{}
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func parseJwkUri(userPoolId string) (string, error) {
	pattern := `^(?P<region>(\w+-)?\w+-\w+-\d)+_\w+$`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(userPoolId)
	if len(match) == 0 {
		return "", fmt.Errorf("invalid Cognito User Pool ID: %s", userPoolId)
	}
	region := match[1]
	uri := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)

	return uri, nil
}

func getRSAPublicKey(jwksUri string, kid string, jwksClient *JwksClient) (*rsa.PublicKey, error) {
	jwks, err := jwksClient.GetJsonWebKeySet(jwksUri)
	if err != nil {
		return nil, err
	}

	keys, ok := jwks["keys"].([]interface{})

	if !ok {
		return nil, fmt.Errorf("invalid key format")
	}

	var temp map[string]interface{}
	for _, key := range keys {
		keyMap, ok := key.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid key format")
		}
		if keyMap["kid"] == kid {
			temp = keyMap
		}
	}
	if temp == nil {
		return nil, fmt.Errorf("public key not found")
	}

	nBytes, _ := base64.RawURLEncoding.DecodeString(temp["n"].(string))
	eBytes, _ := base64.RawURLEncoding.DecodeString(temp["e"].(string))
	e := new(big.Int).SetBytes(eBytes)
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}

	return publicKey, nil
}

func validateJwtString(token string) error {
	pattern := "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
	re := regexp.MustCompile(pattern)
	if !re.MatchString(token) {
		return fmt.Errorf("invalid JWT format")
	}

	return nil
}

func (jwt DeconstructedToken) validateExp() error {
	exp, ok := jwt.Payload["exp"].(float64)
	if !ok {
		return fmt.Errorf("decode error: exp claim is not a number")
	}
	if int64(exp) <= time.Now().Unix() {
		return fmt.Errorf("token is expired")
	}

	return nil
}

func (jwt DeconstructedToken) validateAudience(clientId string) error {
	if v, ok := jwt.Payload["aud"]; ok {
		if v == clientId {
			return nil
		}
	}
	if v, ok := jwt.Payload["client_id"]; ok {
		if v == clientId {
			return nil
		}
	}

	return fmt.Errorf("invalid audience claim")
}

func (jwt DeconstructedToken) validateIssuer(userPoolId string) error {
	iss, ok := jwt.Payload["iss"].(string)
	if !ok {
		return fmt.Errorf("decode error: iss claim must be a string")
	}
	re := regexp.MustCompile(`https://cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/([a-zA-Z0-9_-]+)`)
	matches := re.FindStringSubmatch(iss)
	if matches[2] == userPoolId {
		return nil
	}

	return fmt.Errorf("invalid issuer claim")
}

func (jwt DeconstructedToken) validateSignature(publicKey *rsa.PublicKey) error {
	message := fmt.Sprintf("%s.%s", jwt.B64Header, jwt.B64Payload)
	hashed := sha256.Sum256([]byte(message))
	signature, _ := base64.RawURLEncoding.DecodeString(jwt.B64Signature)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func deconstructJwt(token string) (*DeconstructedToken, error) {
	jwtComponents := strings.Split(token, ".")
	b64Header, b64Payload, b64Signature := jwtComponents[0], jwtComponents[1], jwtComponents[2]
	decodedHeader, err := b64Decode(b64Header)
	if err != nil {
		return nil, err
	}
	decodedPayload, err := b64Decode(b64Payload)
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	err = json.Unmarshal([]byte(decodedHeader), &header)
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, err
	}

	jwt := DeconstructedToken{
		Header:       header,
		Payload:      payload,
		B64Header:    b64Header,
		B64Payload:   b64Payload,
		B64Signature: b64Signature,
		B64Token:     token,
	}

	return &jwt, nil
}

// Validate takes a token string and validates it against the specified user pool and client ID
// using Amazon Cognito's JWT validation rules.
func (c CognitoJwtValidator) Validate(token string) error {
	if err := validateJwtString(token); err != nil {
		return err
	}

	jwksUri, err := parseJwkUri(c.UserPoolId)
	if err != nil {
		return err
	}

	jwt, err := deconstructJwt(token)
	if err != nil {
		return fmt.Errorf("error parsing jwt: %w", err)
	}

	jwksClient := &JwksClient{httpClient: http.DefaultClient}
	publicKey, err := getRSAPublicKey(jwksUri, jwt.Header["kid"].(string), jwksClient)
	if err != nil {
		return err
	}

	var errMsg string
	switch {
	case jwt.validateExp() != nil:
		errMsg += "token is expired."
		break
	case jwt.validateAudience(c.ClientId) != nil:
		errMsg += "invalid audience claim."
		break
	case jwt.validateIssuer(c.UserPoolId) != nil:
		errMsg += "invalid issuer claim."
		break
	case jwt.validateSignature(publicKey) != nil:
		errMsg += "invalid signature."
		break
	default:
		return nil
	}

	return fmt.Errorf("error validating jwt: %s", strings.TrimSpace(errMsg))
}

// NewCognitoJwtValidator returns a new Cognito JWT validator client
func NewCognitoJwtValidator(userPoolId string, clientId string) *CognitoJwtValidator {
	return &CognitoJwtValidator{userPoolId, clientId}
}
