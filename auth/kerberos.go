// Package auth provides authentication methods for NullFang
package auth

import (
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosAuth implements Kerberos authentication
type KerberosAuth struct {
	baseAuth
	domain     string
	username   string
	password   string
	realm      string
	ticketFile string
	keytabFile string
	kdcHost    string
	spn        string
	Ticket     []byte
	TicketPath string
}

// NewKerberosAuth creates a new Kerberos authenticator
func NewKerberosAuth(domain, username string, options ...Option) AuthMethod {
	// Default realm is uppercase domain
	realm := strings.ToUpper(domain)

	auth := &KerberosAuth{
		domain:   domain,
		username: username,
		realm:    realm,
		kdcHost:  "", // Will be determined automatically if not set
	}

	// Apply options
	for _, option := range options {
		option(auth)
	}

	return auth
}

// WithKerberosPassword sets the password for Kerberos authentication
func WithKerberosPassword(password string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.password = password
		}
	}
}

// WithRealm sets the Kerberos realm
func WithRealm(realm string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.realm = realm
		}
	}
}

// WithTicketFile sets the Kerberos ticket file (ccache)
func WithTicketFile(ticketFile string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.ticketFile = ticketFile
		}
	}
}

// WithKeytabFile sets the Kerberos keytab file
func WithKeytabFile(keytabFile string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.keytabFile = keytabFile
		}
	}
}

// WithKDCHost sets the Kerberos KDC host
func WithKDCHost(kdcHost string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.kdcHost = kdcHost
		}
	}
}

// WithSPN sets the Service Principal Name for Kerberos authentication
func WithSPN(spn string) Option {
	return func(a interface{}) {
		if auth, ok := a.(*KerberosAuth); ok {
			auth.spn = spn
		}
	}
}

// Type returns the authentication method type
func (a *KerberosAuth) Type() string {
	return "Kerberos"
}

// Authenticate performs the authentication and returns credentials that can be used with SMB
func (a *KerberosAuth) Authenticate() (*Credentials, error) {
	a.debugLog("Authenticating with Kerberos")

	// If we have a ticket file, use it
	if a.ticketFile != "" {
		return a.authenticateWithTicket()
	}

	// If we have a keytab file, use it
	if a.keytabFile != "" {
		return a.authenticateWithKeytab()
	}

	// If we have a password, get a ticket
	if a.password != "" {
		return a.authenticateWithPassword()
	}

	return nil, ErrMissingCredentials
}

// authenticateWithTicket authenticates using a provided ticket file
func (a *KerberosAuth) authenticateWithTicket() (*Credentials, error) {
	a.debugLog("Using ticket file: %s", a.ticketFile)

	// Check if ticket file exists
	if _, err := os.Stat(a.ticketFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("ticket file not found: %s", a.ticketFile)
	}

	// Load the ticket cache
	ccache, err := credentials.LoadCCache(a.ticketFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load ticket cache: %v", err)
	}

	// Create a new client from the ticket cache
	client, err := client.NewFromCCache(ccache, config.New())
	if err != nil {
		return nil, fmt.Errorf("failed to create client from ticket cache: %v", err)
	}

	// Set the client's configuration
	client.Config.LibDefaults.DNSLookupKDC = true
	client.Config.LibDefaults.DNSLookupRealm = true

	// If we have a KDC host, set it
	if a.kdcHost != "" {
		client.Config.Realms = []config.Realm{
			{
				Realm:       a.realm,
				KDC:         []string{a.kdcHost},
				AdminServer: []string{a.kdcHost},
			},
		}
	}

	// Get a service ticket for the SPN
	spn := a.spn
	if spn == "" {
		spn = GetSPNForHost("cifs", a.domain)
	}

	// Get the ticket
	ticket, key, err := client.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("failed to get service ticket: %v", err)
	}

	// Create SPNEGO token
	// Note: The API for NewKRB5TokenAPREQ has changed in newer versions of gokrb5
	// We're using the updated API signature
	mechTypes := []int{1} // SPNEGO_OID
	apOptions := []int{0} // No options
	token, err := spnego.NewKRB5TokenAPREQ(client, ticket, key, mechTypes, apOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPNEGO token: %v", err)
	}

	// Get the token bytes
	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %v", err)
	}

	// Return the credentials
	return &Credentials{
		Username:   a.username,
		Domain:     a.domain,
		Ticket:     tokenBytes,
		HashType:   "Kerberos",
		SessionKey: key.KeyValue,
	}, nil
}

// authenticateWithKeytab authenticates using a provided keytab file
func (a *KerberosAuth) authenticateWithKeytab() (*Credentials, error) {
	a.debugLog("Using keytab file: %s", a.keytabFile)

	// Check if keytab file exists
	if _, err := os.Stat(a.keytabFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("keytab file not found: %s", a.keytabFile)
	}

	// Load the keytab
	kt, err := keytab.Load(a.keytabFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab: %v", err)
	}

	// Create a new client from the keytab
	client := client.NewWithKeytab(a.username, a.realm, kt, config.New())

	// Set the client's configuration
	client.Config.LibDefaults.DNSLookupKDC = true
	client.Config.LibDefaults.DNSLookupRealm = true

	// If we have a KDC host, set it
	if a.kdcHost != "" {
		client.Config.Realms = []config.Realm{
			{
				Realm:       a.realm,
				KDC:         []string{a.kdcHost},
				AdminServer: []string{a.kdcHost},
			},
		}
	}

	// Login to get the TGT
	err = client.Login()
	if err != nil {
		return nil, fmt.Errorf("failed to login with keytab: %v", err)
	}

	// Get a service ticket for the SPN
	spn := a.spn
	if spn == "" {
		spn = GetSPNForHost("cifs", a.domain)
	}

	// Get the ticket
	ticket, key, err := client.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("failed to get service ticket: %v", err)
	}

	// Create SPNEGO token
	// Note: The API for NewKRB5TokenAPREQ has changed in newer versions of gokrb5
	// We're using the updated API signature
	mechTypes := []int{1} // SPNEGO_OID
	apOptions := []int{0} // No options
	token, err := spnego.NewKRB5TokenAPREQ(client, ticket, key, mechTypes, apOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPNEGO token: %v", err)
	}

	// Get the token bytes
	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %v", err)
	}

	// Return the credentials
	return &Credentials{
		Username:   a.username,
		Domain:     a.domain,
		Ticket:     tokenBytes,
		HashType:   "Kerberos",
		SessionKey: key.KeyValue,
	}, nil
}

// authenticateWithPassword authenticates using a username and password
func (a *KerberosAuth) authenticateWithPassword() (*Credentials, error) {
	a.debugLog("Authenticating with username/password")

	// Create a new client
	client := client.NewWithPassword(a.username, a.realm, a.password, config.New())

	// Set the client's configuration
	client.Config.LibDefaults.DNSLookupKDC = true
	client.Config.LibDefaults.DNSLookupRealm = true

	// If we have a KDC host, set it
	if a.kdcHost != "" {
		client.Config.Realms = []config.Realm{
			{
				Realm:       a.realm,
				KDC:         []string{a.kdcHost},
				AdminServer: []string{a.kdcHost},
			},
		}
	}

	// Login to get the TGT
	err := client.Login()
	if err != nil {
		return nil, fmt.Errorf("failed to login with password: %v", err)
	}

	// Get a service ticket for the SPN
	spn := a.spn
	if spn == "" {
		spn = GetSPNForHost("cifs", a.domain)
	}

	// Get the ticket
	ticket, key, err := client.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("failed to get service ticket: %v", err)
	}

	// Create SPNEGO token
	// Note: The API for NewKRB5TokenAPREQ has changed in newer versions of gokrb5
	// We're using the updated API signature
	mechTypes := []int{1} // SPNEGO_OID
	apOptions := []int{0} // No options
	token, err := spnego.NewKRB5TokenAPREQ(client, ticket, key, mechTypes, apOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPNEGO token: %v", err)
	}

	// Get the token bytes
	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %v", err)
	}

	// Return the credentials
	return &Credentials{
		Username:   a.username,
		Domain:     a.domain,
		Ticket:     tokenBytes,
		HashType:   "Kerberos",
		SessionKey: key.KeyValue,
	}, nil
}

// GetSPNForHost generates a Service Principal Name for a host
func GetSPNForHost(service, host string) string {
	return fmt.Sprintf("%s/%s", service, host)
}

func (k *KerberosAuth) GetCredentials() (*Credentials, error) {
	// Se já temos um ticket carregado, use-o
	if k.Ticket != nil {
		return &Credentials{
			Username:   k.username,
			Domain:     k.domain,
			Ticket:     k.Ticket,
			Method:     "Kerberos",
			HashType:   "Kerberos",
			SessionKey: nil, // Será preenchido pelo SPNEGO
		}, nil
	}

	// Se temos um caminho de ticket, tente autenticar
	if k.TicketPath != "" {
		return k.authenticateWithTicket()
	}

	// Se temos senha, tente autenticar
	if k.password != "" {
		return k.authenticateWithPassword()
	}

	return nil, ErrMissingCredentials
}

func (k *KerberosAuth) GetName() string {
	return "Kerberos"
}

func (k *KerberosAuth) validateTicket(ticket []byte) error {
	// Verifica se o ticket está em formato válido
	if len(ticket) < 10 {
		return fmt.Errorf("ticket muito curto")
	}

	// Verifica o magic number do Kerberos
	if ticket[0] != 0x6a { // ASN.1 sequence
		return fmt.Errorf("ticket não está em formato ASN.1")
	}

	return nil
}
