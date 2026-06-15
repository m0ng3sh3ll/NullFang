package smb2

import (
	. "github.com/m0ng3sh3ll/NullFang/go-smb2-patch/internal/smb2"
)

// client

// Windows 10/11 advertises all 7 capability bits in SMB2 NEGOTIATE.
// Advertising only LARGE_MTU|ENCRYPTION is a known scanner fingerprint.
const (
	clientCapabilities = SMB2_GLOBAL_CAP_DFS |
		SMB2_GLOBAL_CAP_LEASING |
		SMB2_GLOBAL_CAP_LARGE_MTU |
		SMB2_GLOBAL_CAP_MULTI_CHANNEL |
		SMB2_GLOBAL_CAP_PERSISTENT_HANDLES |
		SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
		SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)
