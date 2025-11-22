package login

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var errBadSignature = errors.New("invalid JWT signature")

func decodeBase64URL(value string) ([]byte, error) {
	out, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	return out, nil
}

func decodeJWTParts(token string) (header json.RawMessage, payload json.RawMessage, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("expected 3 JWT parts, got %d", len(parts))
	}
	h, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode JWT header: %w", err)
	}
	p, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	return h, p, nil
}

func parseDERPublicKey(der []byte) (any, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse DER public key: %w", err)
	}
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", key)
	}
}

func checkExpiry(exp, nbf int64, now time.Time) error {
	clockDriftMargin := time.Minute
	if nbf != 0 && now.Add(clockDriftMargin).Before(time.Unix(nbf, 0)) {
		return fmt.Errorf("JWT not yet valid")
	}
	if exp != 0 && now.Add(-clockDriftMargin).After(time.Unix(exp, 0)) {
		return fmt.Errorf("JWT expired")
	}
	return nil
}

func audienceMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func validateSelfSignedClaims(token string, expectedKeyDER []byte, out any) ([]byte, error) {
	headerJSON, _, err := decodeJWTParts(token)
	if err != nil {
		return nil, err
	}
	var header struct {
		Alg string `json:"alg"`
		X5U string `json:"x5u"`
		X5T string `json:"x5t,omitempty"`
	}
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}
	derKey, err := decodeBase64URL(header.X5U)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT public key: %w", err)
	}
	if len(expectedKeyDER) > 0 && !bytes.Equal(derKey, expectedKeyDER) {
		return nil, errBadSignature
	}
	pub, err := parseDERPublicKey(derKey)
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err = parsed.Claims(pub, &claims); err != nil {
		return nil, err
	}
	if out != nil {
		raw, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, out); err != nil {
			return nil, err
		}
	}
	return derKey, nil
}

func validateOpenIDToken(token string, signingKeyDER []byte, issuer string, now time.Time) (*xboxAuthJwtBody, error) {
	pub, err := parseDERPublicKey(signingKeyDER)
	if err != nil {
		return nil, err
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err = parsed.Claims(pub, &claims); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var body xboxAuthJwtBody
	if err = json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if body.Iss != issuer {
		return nil, fmt.Errorf("invalid JWT issuer: %s", body.Iss)
	}
	if !audienceMatches(body.Aud, "api://auth-minecraft-services/multiplayer") {
		return nil, fmt.Errorf("invalid JWT audience")
	}
	if err = checkExpiry(body.Exp, body.Nbf, now); err != nil {
		return nil, err
	}
	return &body, nil
}
