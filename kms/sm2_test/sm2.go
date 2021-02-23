package sm2

type IKMS interface {
	CreateKey() error
	PublicKey() IPubKey
	KeyID() string
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	DeleteKey() error
}

// IPubKey is designed to test compatibility
type IPubKey interface {
	// WriteToPem writes pubKey to pem for tjfoc to load
	WriteToPem() ([]byte, error)
	// ReadFromPem reads pubKey pem from tjfoc
	ReadFromPem([]byte) (IPubKey, error)
}
