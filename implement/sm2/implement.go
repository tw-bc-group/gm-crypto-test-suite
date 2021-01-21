package sm2

type Sm2Creator interface {
	CreateKey() Sm2PrivKeyImpl
}

type Sm2PrivKeyImpl interface {
	PublicKey() Sm2PubKeyImpl
	Sign(message []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (Sm2PrivKeyImpl, error)
}

type Sm2PubKeyImpl interface {
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (Sm2PubKeyImpl, error)
}
