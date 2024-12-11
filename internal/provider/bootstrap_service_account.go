package provider

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func generateBootstrapServiceAccountToken(
	sharedSecretB64 string,
) (string, error) {
	sharedSecret, err := base64.StdEncoding.DecodeString(sharedSecretB64)
	if err != nil {
		return "", fmt.Errorf("shared_secret is invalid: %w", err)
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedSecret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", status.Errorf(codes.Internal, "signing JWT: %s", err.Error())
	}

	var claims struct {
		jwt.Claims
	}
	claims.ID = "014e587b-3f4b-4fcf-90a9-f6ecdf8154af"
	claims.Subject = "bootstrap-014e587b-3f4b-4fcf-90a9-f6ecdf8154af.pomerium"
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)

	rawJWT, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", status.Errorf(codes.Internal, "signing JWT: %s", err.Error())
	}
	return rawJWT, nil
}
