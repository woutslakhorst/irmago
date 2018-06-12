package irma

import (
	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
)

func CreateDisclosureJwt(attributes AttributeDisjunctionList, serverName, humanName string, sk *rsa.PrivateKey) (string, error) {
	claims := ServiceProviderJwt{
		ServerJwt: ServerJwt{
			ServerName: serverName,
			Type:       humanName,
			IssuedAt:   TimestampNow(),
		},
		Request: ServiceProviderRequest{
			Validity: 120,
			Request: &DisclosureRequest{
				Content: attributes,
			},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(sk)
}
