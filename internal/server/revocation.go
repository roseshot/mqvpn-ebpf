package server

// RevocationConfig controls optional RFC 5280 client certificate CRL checks.
// "off" does not disable mutual TLS or peer identity authorization.
type RevocationConfig struct {
	Mode    string `yaml:"mode,omitempty"`
	CRLFile string `yaml:"crl_file,omitempty"`
}

