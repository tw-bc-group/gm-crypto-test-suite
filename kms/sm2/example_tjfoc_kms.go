package sm2

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
)

type KeyAdapter struct {
	keyID     string
	publicKey *sm2.PublicKey
}

var privKey *sm2.PrivateKey

func CreateKeyAdapter() *KeyAdapter {
	return &KeyAdapter{
		keyID:     "12345678",
		publicKey: nil,
	}
}

func (adapter *KeyAdapter) CreateKey() error {
	privKey, _ = sm2.GenerateKey(nil)
	adapter.publicKey = &privKey.PublicKey
	return nil
}

func (adapter *KeyAdapter) PublicKey() *sm2.PublicKey {
	return adapter.publicKey
}

func (adapter *KeyAdapter) KeyID() string {
	return adapter.keyID
}

func (adapter *KeyAdapter) Sign(message []byte) ([]byte, error) {
	return privKey.Sign(rand.Reader, message, nil)
}

func (adapter *KeyAdapter) Verify(message, signature []byte) (bool, error) {
	return adapter.publicKey.Verify(message, signature), nil
}

func (adapter *KeyAdapter) Encrypt(plainText []byte) ([]byte, error) {
	return adapter.publicKey.EncryptAsn1(plainText, rand.Reader)
}

func (adapter *KeyAdapter) Decrypt(cipherText []byte) ([]byte, error) {
	return privKey.DecryptAsn1(cipherText)
}

func (adapter *KeyAdapter) DeleteKey() error {
	return nil
}
