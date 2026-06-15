package smb2

import (
	"encoding/asn1"

	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch/internal/ntlm"
	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch/internal/spnego"
)

type Initiator interface {
	oid() asn1.ObjectIdentifier
	initSecContext() ([]byte, error)            // GSS_Init_sec_context
	acceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	sum(bs []byte) []byte                       // GSS_getMIC
	sessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	ntlm   *ntlm.Client
	seqNum uint32
}

func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMInitiator) initSecContext() ([]byte, error) {
	i.ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        i.Hash,
		Domain:      i.Domain,
		Workstation: i.Workstation,
		TargetSPN:   i.TargetSPN,
	}
	nmsg, err := i.ntlm.Negotiate()
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	return amsg, nil
}

func (i *NTLMInitiator) sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) sessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) infoMap() *ntlm.InfoMap {
	return i.ntlm.Session().InfoMap()
}

// KerberosInitiator implements session-setup through Kerberos/SPNEGO.
// APReq must be the raw GSSAPI KRB5 token bytes (KRB5Token.Marshal() output from gokrb5),
// not a SPNEGO NegTokenInit — spnegoClient wraps it in NegTokenInit automatically.
// SessionKeyBytes is the Kerberos EncryptionKey.KeyValue used to derive SMB2 signing keys.
type KerberosInitiator struct {
	APReq           []byte
	SessionKeyBytes []byte
}

func (i *KerberosInitiator) oid() asn1.ObjectIdentifier {
	return spnego.MsKerberosOid
}

func (i *KerberosInitiator) initSecContext() ([]byte, error) {
	return i.APReq, nil
}

func (i *KerberosInitiator) acceptSecContext(_ []byte) ([]byte, error) {
	// For non-mutual-auth Kerberos the server sends accept-completed;
	// no AP-REP processing is required on the client side.
	return nil, nil
}

func (i *KerberosInitiator) sum(_ []byte) []byte {
	// mechListMIC is optional for Kerberos; Windows accepts nil.
	return nil
}

func (i *KerberosInitiator) sessionKey() []byte {
	// MS-SMB2 §3.3.5.5: Session.SessionKey is the first 16 bytes of the Kerberos session key.
	if len(i.SessionKeyBytes) > 16 {
		return i.SessionKeyBytes[:16]
	}
	return i.SessionKeyBytes
}
