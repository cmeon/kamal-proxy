package certdns01

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"os"
	"path/filepath"
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
	domain  string
	email   string
	cert    *tls.Certificate
	certDir string
	mu      sync.RWMutex
}

func NewDODNS01CertManager(domain, email, certDir string) *DOCertManager {
	return &DOCertManager{
		domain:  strings.TrimPrefix(domain, "*."),
		email:   email,
		certDir: certDir,
	}
}

// HTTPHandler implements [server.CertManager].
func (m *DOCertManager) HTTPHandler(handler http.Handler) http.Handler {
	return handler
}

// GetCertificate implements [server.CertManager].
func (m *DOCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := m.getCert(); cert != nil {
		return cert, nil
	}

	certFile := filepath.Join(m.certDir, m.domain+".crt")
	keyFile := filepath.Join(m.certDir, m.domain+".key")

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		slog.Info("Loaded certificate from disk cache", "domain", m.domain)
		m.mu.Lock()
		m.cert = &tlsCert
		m.mu.Unlock()
		return m.cert, nil
	}

	return m.genCert(certFile, keyFile)
}

func (m *DOCertManager) getCert() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

func (m *DOCertManager) genCert(certFile, keyFile string) (*tls.Certificate, error) {
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
		return nil, err
	}

	if err := os.MkdirAll(m.certDir, 0755); err != nil {
		slog.Error("Failed to create cert directory", "error", err)
	} else {
		os.WriteFile(certFile, certs.Certificate, 0644)
		os.WriteFile(keyFile, certs.PrivateKey, 0600)
		slog.Info("Saved certificate to disk cache", "domain", m.domain)
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
