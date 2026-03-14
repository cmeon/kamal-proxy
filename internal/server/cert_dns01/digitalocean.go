package certdns01

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"strings"

	"log/slog"

	"net/http"

	"sync"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/registration"
)

type DOCertManager struct {
	domain string
	email  string
	cert   *tls.Certificate
	mu     sync.RWMutex
}

func NewDODNS01CertManager(domain, email string) *DOCertManager {
	return &DOCertManager{
		domain: strings.TrimPrefix(domain, "*."),
		email:  email,
	}
}

// HTTPHandler implements [server.CertManager].
func (m *DOCertManager) HTTPHandler(handler http.Handler) http.Handler {
	return handler
}

// GetCertificate implements [server.CertManager].
func (m *DOCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := m.getCert()
	if cert != nil {
		return cert, nil
	}

	return m.genCert()
}

func (m *DOCertManager) getCert() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

func (m *DOCertManager) genCert() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cert != nil {
		return m.cert, nil
	}
	slog.Info("getting DNS-01 certificate via DigitalOcean", "domain", m.domain)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{
		Email: m.email,
		key:   privKey,
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = lego.LEDirectoryProduction
	cfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	provider, err := digitalocean.NewDNSProvider()
	if err != nil {
		return nil, err
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, err
	}
	user.Registration = reg

	req := certificate.ObtainRequest{
		Domains: []string{m.domain, "*." + m.domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(req)
	if err != nil {
		slog.Error("Failed DNS-01 Challenge", "error", err)
	}

	tlsCert, err := tls.X509KeyPair(certs.Certificate, certs.PrivateKey)
	if err != nil {
		return nil, err
	}

	slog.Info("Successfully obtained wildcard SSL certificate via DNS-01")
	m.cert = &tlsCert
	return m.cert, nil
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                       { return u.Email }
func (u acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey       { return u.key }
