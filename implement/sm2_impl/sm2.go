package sm2_impl

type ICreator interface {
	CreateKey() IPrivKey
}

type IPrivKey interface {
	PublicKey() IPubKey
	Sign(message []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (IPrivKey, error)
}

type IPubKey interface {
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	WriteToPem() ([]byte, error)
	ReadFromPem(pem []byte) (IPubKey, error)
}
