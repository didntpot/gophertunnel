package login

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

const (
	AuthTypeFull = iota
	AuthTypeGuest
	AuthTypeSelfSigned
)

// chain holds a chain with claims, each with their own headers, payloads and signatures. Each claim holds
// a public key used to verify other claims.
type chain []string

type certificate struct {
	Chain chain `json:"chain"`
}

// request is the outer encapsulation of the request. It holds a chain and a ClientData object.
type request struct {
	// Certificate holds the client certificate chain. The chain holds several claims that the server may verify in order to
	// make sure that the client is logged into XBOX Live.
	Certificate certificate `json:"Certificate"`
	// AuthenticationType is the authentication type of the request.
	AuthenticationType uint8 `json:"AuthenticationType"`
	// Token is an empty string, it's unclear what's used for.
	Token string `json:"Token"`
	// RawToken holds the raw token that follows the JWT chain, holding the ClientData.
	RawToken string `json:"-"`
	// Legacy specifies whether to use the legacy format of the request or not.
	Legacy bool `json:"-"`
}

func (r *request) MarshalJSON() ([]byte, error) {
	if r.Legacy {
		return json.Marshal(r.Certificate)
	}

	cert, err := json.Marshal(r.Certificate)
	if err != nil {
		return nil, err
	}

	type Alias request
	return json.Marshal(&struct {
		Certificate string `json:"Certificate"`
		Alias
	}{
		Certificate: string(cert),
		Alias:       (Alias)(*r),
	})
}

// AuthResult is returned by a call to Parse. It holds the ecdsa.PublicKey of the client and a bool that
// indicates if the player was logged in with XBOX Live.
type AuthResult struct {
	PublicKey             *ecdsa.PublicKey
	XBOXLiveAuthenticated bool
}

// Parse parses and verifies the login request passed. The AuthResult returned holds the ecdsa.PublicKey that
// was parsed (which is used for encryption) and a bool specifying if the request was authenticated by XBOX
// Live.
// Parse returns IdentityData and ClientData, of which IdentityData cannot under any circumstance be edited by
// the client. Rather, it is obtained from an authentication endpoint. The ClientData can, however, be edited
// freely by the client.
func Parse(requestData []byte) (IdentityData, ClientData, AuthResult, error) {
	var (
		iData IdentityData
		cData ClientData
		res   AuthResult
	)
	authInfoJSON, clientDataJWT, err := readConnectionRequest(bytes.NewBuffer(requestData))
	if err != nil {
		return iData, cData, res, err
	}

	var info struct {
		AuthenticationType int    `json:"AuthenticationType"`
		Certificate        string `json:"Certificate"`
		Token              string `json:"Token"`
	}
	if err = json.Unmarshal(authInfoJSON, &info); err != nil {
		return iData, cData, res, fmt.Errorf("decode auth info: %w", err)
	}

	switch info.AuthenticationType {
	case AuthTypeFull:
		return parseFullAuth(info.Token, string(clientDataJWT))
	case AuthTypeSelfSigned:
		return parseSelfSignedAuth(info.Certificate, string(clientDataJWT))
	default:
		return iData, cData, res, fmt.Errorf("unsupported authentication type: %d", info.AuthenticationType)
	}
}

// readConnectionRequest extracts the auth info JSON and client data JWT slices from the login connection request buffer.
func readConnectionRequest(buf *bytes.Buffer) ([]byte, []byte, error) {
	var authLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &authLen); err != nil {
		return nil, nil, fmt.Errorf("read auth info length: %w", err)
	}
	authInfoJSON := buf.Next(int(authLen))
	if len(authInfoJSON) != int(authLen) {
		return nil, nil, fmt.Errorf("auth info truncated: expected %d bytes, got %d", authLen, len(authInfoJSON))
	}
	var clientLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &clientLen); err != nil {
		return nil, nil, fmt.Errorf("read client data length: %w", err)
	}
	clientDataJWT := buf.Next(int(clientLen))
	if len(clientDataJWT) != int(clientLen) {
		return nil, nil, fmt.Errorf("client data truncated: expected %d bytes, got %d", clientLen, len(clientDataJWT))
	}
	return authInfoJSON, clientDataJWT, nil
}

// Encode encodes a login request using the encoded login chain passed and the client data. The request's
// client data token is signed using the private key passed. It must be the same as the one used to get the
// login chain.
func Encode(loginChain string, data ClientData, key *ecdsa.PrivateKey, legacy bool) []byte {
	// We first decode the login chain we actually got in a new certificate.
	cert := &certificate{}
	_ = json.Unmarshal([]byte(loginChain), &cert)

	// We parse the header of the first claim it has in the chain, which will soon be the second claim.
	keyData := MarshalPublicKey(&key.PublicKey)
	tok, _ := jwt.ParseSigned(cert.Chain[0], []jose.SignatureAlgorithm{jose.ES384})

	//lint:ignore S1005 Double assignment is done explicitly to prevent panics.
	x5uData, _ := tok.Headers[0].ExtraHeaders["x5u"]
	x5u, _ := x5uData.(string)
	claims := jwt.Claims{
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour * 6)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour * 6)),
	}

	signer, _ := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": keyData},
	})
	firstJWT, _ := jwt.Signed(signer).Claims(identityPublicKeyClaims{
		Claims:               claims,
		IdentityPublicKey:    x5u,
		CertificateAuthority: true,
	}).Serialize()

	req := &request{
		Certificate: certificate{
			// We add our own claim at the start of the chain.
			Chain: append(chain{firstJWT}, cert.Chain...),
		},
		AuthenticationType: AuthTypeFull,
		Legacy:             legacy,
	}
	// We create another token this time, which is signed the same as the claim we just inserted in the chain,
	// just now it contains client data.
	req.RawToken, _ = jwt.Signed(signer).Claims(data).Serialize()

	return encodeRequest(req)
}

// encodeRequest encodes the request passed to a byte slice which is suitable for setting to the Connection
// Request field in a Login packet.
func encodeRequest(req *request) []byte {
	chainBytes, _ := json.Marshal(req)

	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, int32(len(chainBytes)))
	_, _ = buf.WriteString(string(chainBytes))

	_ = binary.Write(buf, binary.LittleEndian, int32(len(req.RawToken)))
	_, _ = buf.WriteString(req.RawToken)
	return buf.Bytes()
}

// EncodeOffline creates a login request using the identity data and client data passed. The private key
// passed will be used to self sign the JWTs.
// Unlike Encode, EncodeOffline does not have a token signed by the Mojang key. It consists of only one JWT
// which holds the identity data of the player.
func EncodeOffline(identityData IdentityData, data ClientData, key *ecdsa.PrivateKey, legacy bool) []byte {
	keyData := MarshalPublicKey(&key.PublicKey)
	claims := jwt.Claims{
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour * 6)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour * 6)),
	}

	signer, _ := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": keyData},
	})
	firstJWT, _ := jwt.Signed(signer).Claims(identityClaims{
		Claims:            claims,
		ExtraData:         identityData,
		IdentityPublicKey: keyData,
	}).Serialize()

	req := &request{
		Certificate: certificate{
			Chain: chain{firstJWT},
		},
		AuthenticationType: AuthTypeSelfSigned,
		Legacy:             legacy,
	}
	// We create another token this time, which is signed the same as the claim we just inserted in the chain,
	// just now it contains client data.
	req.RawToken, _ = jwt.Signed(signer).Claims(data).Serialize()

	return encodeRequest(req)
}

// identityClaims holds the claims for the last token in the chain, which contains the IdentityData of the
// player.
type identityClaims struct {
	jwt.Claims

	// ExtraData holds the extra data of this claim, which is the IdentityData of the player.
	ExtraData IdentityData `json:"extraData"`

	IdentityPublicKey string `json:"identityPublicKey"`
}

// Validate validates the identity claims held by the struct and returns an error if any illegal data was
// encountered.
func (c identityClaims) Validate(e jwt.Expected) error {
	if err := c.Claims.Validate(e); err != nil {
		return err
	}
	return c.ExtraData.Validate()
}

// identityPublicKeyClaims holds the claims for a JWT that holds an identity public key.
type identityPublicKeyClaims struct {
	jwt.Claims

	// IdentityPublicKey holds a serialised ecdsa.PublicKey used in the next JWT in the chain.
	IdentityPublicKey    string `json:"identityPublicKey"`
	CertificateAuthority bool   `json:"certificateAuthority,omitempty"`
}

// ParsePublicKey parses an ecdsa.PublicKey from the base64 encoded public key data passed and sets it to a
// pointer. If parsing failed or if the public key was not of the type ECDSA, an error is returned.
func ParsePublicKey(b64Data string, key *ecdsa.PublicKey) error {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return fmt.Errorf("decode public key data: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected ECDSA public key, got %v", key)
	}
	*key = *ecdsaKey
	return nil
}

// MarshalPublicKey marshals an ecdsa.PublicKey to a base64 encoded binary representation.
func MarshalPublicKey(key *ecdsa.PublicKey) string {
	data, _ := x509.MarshalPKIXPublicKey(key)
	return base64.StdEncoding.EncodeToString(data)
}

type xboxAuthJwtBody struct {
	Ipt   string `json:"ipt"`
	Pfcd  int64  `json:"pfcd"`
	Tid   string `json:"tid"`
	Mid   string `json:"mid"`
	Xid   string `json:"xid"`
	Xname string `json:"xname"`
	Cpk   string `json:"cpk"`

	Pid   string `json:"pid"`
	Pname string `json:"pname"`

	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

func parseFullAuth(openIDToken string, clientJWT string) (IdentityData, ClientData, AuthResult, error) {
	var zeroID IdentityData
	var zeroCD ClientData
	var zeroRes AuthResult

	headerJSON, _, err := decodeJWTParts(openIDToken)
	if err != nil {
		return zeroID, zeroCD, zeroRes, err
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err = json.Unmarshal(headerJSON, &hdr); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("parse OpenID header: %w", err)
	}

	issuer, signingKeyDER, err := defaultAuthKeyProvider.GetKey(context.Background(), hdr.Kid)
	if err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("fetch authentication key: %w", err)
	}

	body, err := validateOpenIDToken(openIDToken, signingKeyDER, issuer, time.Now())
	if err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate OpenID token: %w", err)
	}

	clientKeyDER, err := decodeBase64URL(body.Cpk)
	if err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("decode client key: %w", err)
	}

	var clientData ClientData
	if _, err = validateSelfSignedClaims(clientJWT, clientKeyDER, &clientData); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate client data JWT: %w", err)
	}
	if err = clientData.Validate(); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate client data: %w", err)
	}

	legacyUUID := calculateUUIDFromXUID(body.Xid)
	idData := IdentityData{
		XUID:        body.Xid,
		Identity:    legacyUUID.String(),
		DisplayName: body.Xname,
	}
	if err = idData.Validate(); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate identity: %w", err)
	}

	pubAny, err := parseDERPublicKey(clientKeyDER)
	if err != nil {
		return zeroID, zeroCD, zeroRes, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("expected ECDSA client key")
	}

	return idData, clientData, AuthResult{PublicKey: pub, XBOXLiveAuthenticated: true}, nil
}

func parseSelfSignedAuth(cert string, clientJWT string) (IdentityData, ClientData, AuthResult, error) {
	var zeroID IdentityData
	var zeroCD ClientData
	var zeroRes AuthResult

	var chain struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(cert), &chain); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("parse self-signed certificate: %w", err)
	}
	if len(chain.Chain) != 1 {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("expected exactly one certificate in self-signed chain, got %d", len(chain.Chain))
	}

	identityData, err := parseLegacyIdentity(chain.Chain[0])
	if err != nil {
		return zeroID, zeroCD, zeroRes, err
	}
	if err = identityData.Validate(); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate identity: %w", err)
	}

	clientKeyDER, authenticated, err := validateLegacyChain(chain.Chain, nil, time.Now())
	if err != nil {
		return zeroID, zeroCD, zeroRes, err
	}
	var clientData ClientData
	if _, err = validateSelfSignedClaims(clientJWT, clientKeyDER, &clientData); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate client data JWT: %w", err)
	}
	if err = clientData.Validate(); err != nil {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("validate client data: %w", err)
	}

	pubAny, err := parseDERPublicKey(clientKeyDER)
	if err != nil {
		return zeroID, zeroCD, zeroRes, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return zeroID, zeroCD, zeroRes, fmt.Errorf("expected ECDSA client key")
	}

	return identityData, clientData, AuthResult{PublicKey: pub, XBOXLiveAuthenticated: authenticated}, nil
}

func parseLegacyIdentity(token string) (IdentityData, error) {
	_, payload, err := decodeJWTParts(token)
	if err != nil {
		return IdentityData{}, err
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(payload, &raw); err != nil {
		return IdentityData{}, fmt.Errorf("parse legacy payload: %w", err)
	}
	extra, ok := raw["extraData"]
	if !ok {
		return IdentityData{}, fmt.Errorf("missing extraData in self-signed certificate")
	}
	var identity IdentityData
	if err = json.Unmarshal(extra, &identity); err != nil {
		return IdentityData{}, fmt.Errorf("decode extraData: %w", err)
	}
	return identity, nil
}

func validateLegacyChain(chain []string, rootAuthKeyDER []byte, now time.Time) ([]byte, bool, error) {
	identityKey := rootAuthKeyDER
	authenticated := false

	for idx, jwtString := range chain {
		var claims struct {
			IdentityPublicKey string `json:"identityPublicKey"`
			Exp               int64  `json:"exp"`
			Nbf               int64  `json:"nbf"`
		}
		if _, err := validateSelfSignedClaims(jwtString, identityKey, &claims); err != nil {
			return nil, false, fmt.Errorf("validate chain link %d: %w", idx, err)
		}
		if err := checkExpiry(claims.Exp, claims.Nbf, now); err != nil {
			return nil, false, fmt.Errorf("chain link %d expired: %w", idx, err)
		}
		if len(rootAuthKeyDER) > 0 && bytes.Equal(identityKey, rootAuthKeyDER) {
			authenticated = true
		}
		if claims.IdentityPublicKey == "" {
			return nil, false, fmt.Errorf("missing identityPublicKey in chain link %d", idx)
		}
		nextKey, err := decodeBase64URL(claims.IdentityPublicKey)
		if err != nil {
			return nil, false, fmt.Errorf("invalid identityPublicKey in chain link %d: %w", idx, err)
		}
		identityKey = nextKey
	}
	if identityKey == nil {
		return nil, false, fmt.Errorf("no authentication chain links provided")
	}
	return identityKey, authenticated, nil
}

func calculateUUIDFromXUID(xuid string) uuid.UUID {
	hash := md5.Sum([]byte("pocket-auth-1-xuid:" + xuid))
	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80
	return uuid.Must(uuid.FromBytes(hash[:]))
}
