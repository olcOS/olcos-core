package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// generateCert makes a self-signed ECDSA P-256 certificate valid for ten
// years, with the server's address as its SAN (an IP SAN when host is an IP,
// otherwise a DNS SAN). It returns the certificate and key as PEM plus the
// lowercase hex SHA-256 of the certificate DER — the value the app pins.
func generateCert(host string) (certPEM, keyPEM, certSHA string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(der)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, hex.EncodeToString(sum[:]), nil
}

// deviceIDFromSPKI derives a device id: the first 16 characters of the
// unpadded base64url of SHA-256 over the SPKI DER. Stable for a given key.
func deviceIDFromSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return b64url(sum[:])[:16]
}

// certSHAFromPEM recomputes the pinned hash from a certificate PEM (used when
// serving, to be sure the stored hash matches the stored certificate).
func certSHAFromPEM(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate in PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
