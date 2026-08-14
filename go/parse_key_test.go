//revive:disable:package-comments
package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	libjwt "api/lib/jwt"

	"github.com/golang-jwt/jwt/v5"
)

func TestParsePrivateKey_RS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemData := EncodePEMPrivateKey(key)

	privateKey, publicKey, signingMethod, err := libjwt.ParsePrivateKey(pemData, "RS256")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if privateKey == nil {
		t.Error("expected non-nil private key")
	}
	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod != jwt.SigningMethodRS256 {
		t.Errorf("expected RS256, got %v", signingMethod)
	}
}

func TestParsePrivateKey_RS384(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemData := EncodePEMPrivateKey(key)

	privateKey, publicKey, signingMethod, err := libjwt.ParsePrivateKey(pemData, "RS384")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if privateKey == nil {
		t.Error("expected non-nil private key")
	}
	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod != jwt.SigningMethodRS384 {
		t.Errorf("expected RS384, got %v", signingMethod)
	}
}

func TestParsePrivateKey_RS512(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemData := EncodePEMPrivateKey(key)

	privateKey, publicKey, signingMethod, err := libjwt.ParsePrivateKey(pemData, "RS512")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if privateKey == nil {
		t.Error("expected non-nil private key")
	}
	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod != jwt.SigningMethodRS512 {
		t.Errorf("expected RS512, got %v", signingMethod)
	}
}

func TestParsePrivateKey_PKCS8Format(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemData, err := EncodePEMPrivateKeyPKCS8(key)
	if err != nil {
		t.Fatalf("failed to encode key: %v", err)
	}

	privateKey, publicKey, signingMethod, err := libjwt.ParsePrivateKey(pemData, "RS256")
	if err != nil {
		t.Fatalf("expected success with PKCS8 format, got error: %v", err)
	}

	if privateKey == nil {
		t.Error("expected non-nil private key")
	}
	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod != jwt.SigningMethodRS256 {
		t.Errorf("expected RS256, got %v", signingMethod)
	}
}

func TestParsePrivateKey_ECDSANotSupported(t *testing.T) {
	algorithms := []string{"ES256", "ES384", "ES512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			_, _, _, err := libjwt.ParsePrivateKey("", alg)
			if err == nil {
				t.Errorf("expected error for %s, got nil", alg)
			}
			if err.Error() != "ECDSA not yet supported" {
				t.Errorf("expected 'ECDSA not yet supported', got '%v'", err)
			}
		})
	}
}

func TestParsePrivateKey_HMACNotSupported(t *testing.T) {
	algorithms := []string{"HS256", "HS384", "HS512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			_, _, _, err := libjwt.ParsePrivateKey("", alg)
			if err == nil {
				t.Errorf("expected error for %s, got nil", alg)
			}
			if err.Error() != "HMAC not supported (use asymmetric keys)" {
				t.Errorf("expected 'HMAC not supported (use asymmetric keys)', got '%v'", err)
			}
		})
	}
}

func TestParsePrivateKey_UnsupportedAlgorithm(t *testing.T) {
	_, _, _, err := libjwt.ParsePrivateKey("", "UNKNOWN")
	if err == nil {
		t.Error("expected error for unsupported algorithm, got nil")
	}
	if err.Error() != "unsupported algorithm: UNKNOWN" {
		t.Errorf("expected 'unsupported algorithm: UNKNOWN', got '%v'", err)
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	_, _, _, err := libjwt.ParsePrivateKey("not valid pem data", "RS256")
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
	if err.Error() != "failed to decode PEM block" {
		t.Errorf("expected 'failed to decode PEM block', got '%v'", err)
	}
}

func TestParsePrivateKey_EmptyPEM(t *testing.T) {
	_, _, _, err := libjwt.ParsePrivateKey("", "RS256")
	if err == nil {
		t.Error("expected error for empty PEM, got nil")
	}
}

func TestParsePrivateKey_WrongKeyTypeInPEM(t *testing.T) {
	// Create a PEM block with garbage data that's not a valid key
	garbagePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("this is not a valid key"),
	})

	_, _, _, err := libjwt.ParsePrivateKey(string(garbagePEM), "RS256")
	if err == nil {
		t.Error("expected error for invalid key data, got nil")
	}
}

func TestParsePrivateKey_RS384_InvalidPEM(t *testing.T) {
	_, _, _, err := libjwt.ParsePrivateKey("not valid pem data", "RS384")
	if err == nil {
		t.Error("expected error for invalid PEM with RS384, got nil")
	}
}

func TestParsePrivateKey_RS512_InvalidPEM(t *testing.T) {
	_, _, _, err := libjwt.ParsePrivateKey("not valid pem data", "RS512")
	if err == nil {
		t.Error("expected error for invalid PEM with RS512, got nil")
	}
}

func TestParsePrivateKey_PKCS8_NonRSAKey(t *testing.T) {
	// Create an ECDSA key and encode it as PKCS8
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	_, _, _, err = libjwt.ParsePrivateKey(string(pemData), "RS256")
	if err == nil {
		t.Error("expected error for non-RSA key in PKCS8, got nil")
	}
	if err.Error() != "key is not RSA private key" {
		t.Errorf("expected 'key is not RSA private key', got '%v'", err)
	}
}

func TestParsePrivateKey_PublicKeyCanSign(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pemData := EncodePEMPrivateKey(key)

	privateKey, publicKey, signingMethod, err := libjwt.ParsePrivateKey(pemData, "RS256")
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}

	// Create and sign a token
	claims := jwt.MapClaims{"sub": "test-user"}
	token := jwt.NewWithClaims(signingMethod, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Verify with the returned public key
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if !parsedToken.Valid {
		t.Error("token should be valid")
	}
}
