package sm2

import "github.com/Hyperledger-TWGC/tjfoc-gm/sm2"

type Sm2KMS interface {
	CreateKey() error
	PublicKey() *sm2.PublicKey
	KeyID() string
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) (bool, error)
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(cipherText []byte) ([]byte, error)
	DeleteKey() error
}
