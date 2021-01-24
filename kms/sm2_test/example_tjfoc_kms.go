package sm2

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

// PubKey implements Sm2PubKey interface
type PubKey struct {
	publicKey *sm2.PublicKey
}

func (pubKey *PubKey) WriteToPem() ([]byte, error) {
	return x509.WritePublicKeyToPem(pubKey.publicKey)
}

func (pubKey *PubKey) ReadFromPem(pubKeyPem []byte) (Sm2PubKey, error) {
	pub, err := x509.ReadPublicKeyFromPem(pubKeyPem)
	if err != nil {
		return nil, err
	}
	return &PubKey{publicKey: pub}, nil
}

// KeyAdapter implements Sm2KMS interface
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

func (adapter *KeyAdapter) PublicKey() Sm2PubKey {
	return &PubKey{
		publicKey: adapter.publicKey,
	}
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
