package risk

import "strings"

type CipherType string

const (
	CipherAEAD    CipherType = "AEAD"
	CipherBlock   CipherType = "BLOCK"
	CipherStream  CipherType = "STREAM"
	CipherUnknown CipherType = "UNKNOWN"
)

type CipherInfo struct {
	Name           string
	Type           CipherType
	IsAEAD         bool
	IsWeak         bool
	KeySize        int
	KeyExchangeAlg string
	IsPFS          bool
}

func ClassifyCipher(name string) CipherInfo {
	info := CipherInfo{
		Name:           name,
		Type:           CipherUnknown,
		IsAEAD:         false,
		IsWeak:         false, // UNKNOWN ≠ VULNERABLE
		KeySize:        0,
		KeyExchangeAlg: "UNKNOWN",
		IsPFS:          false,
	}

	upperName := strings.ToUpper(name)

	// Key Exchange / PFS
	if strings.Contains(upperName, "ECDHE") || strings.Contains(upperName, "DHE") {
		info.IsPFS = true
		info.KeyExchangeAlg = "ECDHE/DHE"
	} else if strings.Contains(upperName, "RSA") {
		info.KeyExchangeAlg = "RSA"
	}

	// TLS 1.3 Ciphers
	if upperName == "TLS_AES_128_GCM_SHA256" || upperName == "TLS_AES_256_GCM_SHA384" || upperName == "TLS_CHACHA20_POLY1305_SHA256" {
		info.IsPFS = true // TLS 1.3 implies PFS
		info.IsAEAD = true
		info.IsWeak = false
		info.Type = CipherAEAD
		if strings.Contains(upperName, "128") {
			info.KeySize = 128
		} else {
			info.KeySize = 256
		}
		info.KeyExchangeAlg = "TLS1.3"
		return info
	}

	// AEAD vs Block/Stream
	if strings.Contains(upperName, "GCM") || strings.Contains(upperName, "POLY1305") || strings.Contains(upperName, "CCM") {
		info.IsAEAD = true
		info.Type = CipherAEAD
		info.IsWeak = false
	} else if strings.Contains(upperName, "CBC") {
		info.Type = CipherBlock
		info.IsWeak = true // Non-AEAD is considered weak in modern context
	} else if strings.Contains(upperName, "RC4") {
		info.Type = CipherStream
		info.IsWeak = true
	}

	// Key Size
	if strings.Contains(upperName, "256") {
		info.KeySize = 256
	} else if strings.Contains(upperName, "128") {
		info.KeySize = 128
	} else if strings.Contains(upperName, "3DES") {
		info.KeySize = 112
		info.IsWeak = true
	} else if strings.Contains(upperName, "DES") {
		info.KeySize = 56
		info.IsWeak = true
	}

	// Explicit weaknesses
	if strings.Contains(upperName, "MD5") || strings.Contains(upperName, "NULL") || strings.Contains(upperName, "EXPORT") {
		info.IsWeak = true
	}

	return info
}
