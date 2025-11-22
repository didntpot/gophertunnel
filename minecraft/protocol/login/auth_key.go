package login

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

var defaultAuthKeyProvider = newAuthKeyProvider()

type authKeyProvider struct {
	client             *http.Client
	keys               map[string][]byte
	issuer             string
	lastSeen           time.Time
	keyRefreshInterval time.Duration
	mu                 sync.Mutex
}

func newAuthKeyProvider() *authKeyProvider {
	return &authKeyProvider{
		client:             &http.Client{Timeout: 10 * time.Second},
		keyRefreshInterval: 30 * time.Minute,
		keys:               map[string][]byte{},
	}
}

func (provider *authKeyProvider) GetKey(ctx context.Context, keyID string) (string, []byte, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()

	if der, ok := provider.keys[keyID]; ok && time.Since(provider.lastSeen) < provider.keyRefreshInterval {
		return provider.issuer, der, nil
	}

	if err := provider.refreshKeys(ctx); err != nil {
		return "", nil, err
	}
	if der, ok := provider.keys[keyID]; ok {
		return provider.issuer, der, nil
	}
	return "", nil, fmt.Errorf("unrecognised authentication key ID: %s", keyID)
}

func (provider *authKeyProvider) refreshKeys(ctx context.Context) error {
	authURL, err := provider.discoverAuthURL(ctx)
	if err != nil {
		authURL = "https://authorization.franchise.minecraft-services.net"
	}

	issuer, jwksURL, err := provider.fetchOpenIDConfig(ctx, authURL)
	if err != nil {
		issuer = authURL
		jwksURL = authURL + "/.well-known/keys"
	}

	keys, err := provider.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return err
	}

	provider.keys = keys
	provider.issuer = issuer
	provider.lastSeen = time.Now()
	return nil
}

func (provider *authKeyProvider) discoverAuthURL(ctx context.Context) (string, error) {
	res, err := provider.request(ctx, "https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/"+protocol.CurrentVersion)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var out struct {
		Result struct {
			ServiceEnvironments struct {
				Auth struct {
					Prod struct {
						ServiceURI string `json:"serviceUri"`
					} `json:"prod"`
				} `json:"auth"`
			} `json:"serviceEnvironments"`
		} `json:"result"`
	}
	if err = json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode discovery response: %w", err)
	}
	if out.Result.ServiceEnvironments.Auth.Prod.ServiceURI == "" {
		return "", fmt.Errorf("discovery missing serviceUri")
	}
	return out.Result.ServiceEnvironments.Auth.Prod.ServiceURI, nil
}

func (provider *authKeyProvider) fetchOpenIDConfig(ctx context.Context, baseURL string) (string, string, error) {
	res, err := provider.request(ctx, baseURL+"/.well-known/openid-configuration")
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	var cfg struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err = json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return "", "", fmt.Errorf("decode openid configuration: %w", err)
	}
	if cfg.Issuer == "" || cfg.JWKSURI == "" {
		return "", "", fmt.Errorf("invalid openid configuration")
	}
	return cfg.Issuer, cfg.JWKSURI, nil
}

func (provider *authKeyProvider) fetchJWKS(ctx context.Context, url string) (map[string][]byte, error) {
	res, err := provider.request(ctx, url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err = json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := map[string][]byte{}
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := rsaPublicKeyModExpToDER(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid authentication keys returned")
	}
	return keys, nil
}

func (provider *authKeyProvider) request(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := provider.client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		if err = res.Body.Close(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected status code %d for %s", res.StatusCode, url)
	}
	return res, nil
}

func rsaPublicKeyModExpToDER(nBase64, eBase64 string) ([]byte, error) {
	modBytes, err := base64.RawURLEncoding.DecodeString(nBase64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	expBytes, err := base64.RawURLEncoding.DecodeString(eBase64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	mod := new(big.Int).SetBytes(modBytes)
	exp := new(big.Int).SetBytes(expBytes)
	pub := rsa.PublicKey{N: mod, E: int(exp.Int64())}
	der, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA key: %w", err)
	}
	return der, nil
}
