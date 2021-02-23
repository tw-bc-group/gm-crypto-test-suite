package sm2

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

// PubKey implements interface PubKeyImpl
type PubKey struct {
	pubKey sm2.PublicKey
}

func (pubKey *PubKey) Verify(message, signature []byte) (bool, error) {
	return pubKey.pubKey.Verify(message, signature), nil
}

func (pubKey *PubKey) Encrypt(plainText []byte) ([]byte, error) {
	return pubKey.pubKey.EncryptAsn1(plainText, rand.Reader)
}

func (pubKey *PubKey) WriteToPem() ([]byte, error) {
	return x509.WritePublicKeyToPem(&pubKey.pubKey)
}

func (pubKey *PubKey) ReadFromPem(pem []byte) (PubKeyImpl, error) {
	readPubKey, err := x509.ReadPublicKeyFromPem(pem)
	if err != nil {
		return nil, err
	}
	return &PubKey{pubKey: *readPubKey}, nil
}

// PrivKey implements interface PrivKeyImpl
type PrivKey struct {
	privKey sm2.PrivateKey
}

func (privKey *PrivKey) PublicKey() PubKeyImpl {
	return &PubKey{pubKey: privKey.privKey.PublicKey}
}

func (privKey *PrivKey) Sign(message []byte) ([]byte, error) {
	return privKey.privKey.Sign(rand.Reader, message, nil)
}

func (privKey *PrivKey) Decrypt(cipherText []byte) ([]byte, error) {
	return privKey.privKey.DecryptAsn1(cipherText)
}

func (privKey *PrivKey) WriteToPem() ([]byte, error) {
	return x509.WritePrivateKeyToPem(&privKey.privKey, nil)
}

func (privKey *PrivKey) ReadFromPem(pem []byte) (PrivKeyImpl, error) {
	readPrivKey, err := x509.ReadPrivateKeyFromPem(pem, nil)
	if err != nil {
		return nil, err
	}
	return &PrivKey{privKey: *readPrivKey}, nil
}

// KeyCreator implements Creator interface
type KeyCreator struct{}

func (creator *KeyCreator) CreateKey() PrivKeyImpl {
	privKey, err := sm2.GenerateKey(nil)
	if err != nil {
		return nil
	}
	return &PrivKey{privKey: *privKey}
}
