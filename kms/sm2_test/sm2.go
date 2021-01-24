package sm2

type Sm2KMS interface {
	CreateKey() error
	PublicKey() Sm2PubKey
	KeyID() string
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	DeleteKey() error
}

// Sm2PubKey is designed to test compatibility
type Sm2PubKey interface {
	// WriteToPem writes pubKey to pem for tjfoc to load
	WriteToPem() ([]byte, error)
	// ReadFromPem reads pubKey pem from tjfoc
	ReadFromPem([]byte) (Sm2PubKey, error)
}
