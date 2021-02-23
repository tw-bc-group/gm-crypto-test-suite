package sm2

type Creator interface {
	CreateKey() PrivKeyImpl
}

type PrivKeyImpl interface {
	PublicKey() PubKeyImpl
	Sign(message []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (PrivKeyImpl, error)
}

type PubKeyImpl interface {
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (PubKeyImpl, error)
}
