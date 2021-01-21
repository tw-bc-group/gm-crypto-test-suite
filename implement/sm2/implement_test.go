package sm2

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func initImpl() Sm2Creator {
	// ToDo When Test: Replace your own sm2 implement
	//   that implements interface Sm2Creator
	return &KeyCreator{}
}

// TestCreateKeyAndSavePubKeyPem tests CreateKey() then
//   save pubKey to pem and read by tjfoc.
func TestCreateKeyAndSavePubKeyPem(t *testing.T) {
	keyCreator := initImpl()
	pubKey := keyCreator.CreateKey().PublicKey()
	assert.NotNil(t, pubKey, "init failed")

	// kms key -> pem -> tjfoc key
	pubKeyPem, err := pubKey.WriteToPem()
	assert.Nil(t, err, "kms pub key write to pem failed")
	tjPubKey, err := x509.ReadPublicKeyFromMem(pubKeyPem)
	assert.Nil(t, err, "read pem from kms pub key failed")

	// tjfoc key -> pem -> new kms key
	tjPubKeyPem, err := x509.WritePublicKeyToMem(tjPubKey)
	assert.Nil(t, err, "tjfoc pub key write to pem failed")
	transformedPubKey, err := pubKey.ReadFromPem(tjPubKeyPem)
	assert.Nil(t, err, "kms pub key read from tjfoc failed")

	// compare new kms key with origin
	transformedPubKeyPem, err := transformedPubKey.WriteToPem()
	assert.Nil(t, err, "transformed kms pub key write to pem failed")
	assert.Equal(t, pubKeyPem, transformedPubKeyPem, "transformed kms should equal the origin one")
}

// TestCreateKeyAndSavePrivKeyPem tests CreateKey() then
//   save privKey to pem and read by tjfoc.
func TestCreateKeyAndSavePrivKeyPem(t *testing.T) {
	keyCreator := KeyCreator{}
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")

	// kms key -> pem -> tjfoc key
	privKeyPem, err := privKey.WriteToPem()
	assert.Nil(t, err, "kms pub key write to pem failed")
	tjPrivKey, err := x509.ReadPrivateKeyFromMem(privKeyPem, nil)
	assert.Nil(t, err, "read pem from kms pub key failed")

	// tjfoc key -> pem -> new kms key
	tjPrivKeyPem, err := x509.WritePrivateKeyToMem(tjPrivKey, nil)
	assert.Nil(t, err, "tjfoc pub key write to pem failed")
	transformedPrivKey, err := privKey.ReadFromPem(tjPrivKeyPem)
	assert.Nil(t, err, "kms pub key read from tjfoc failed")

	// compare new kms key with origin
	transformedPrivKeyPem, err := transformedPrivKey.WriteToPem()
	assert.Nil(t, err, "transformed kms pub key write to pem failed")
	assert.Equal(t, privKeyPem, transformedPrivKeyPem, "transformed kms should equal the origin one")
}

// TestEncryptAndDecrypt tests Encrypt() and Decrypt()
//   methods by impl self.
func TestEncryptAndDecrypt(t *testing.T) {
	keyCreator := KeyCreator{}
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")

	plainText := []byte("plain text")
	cipherText, err := privKey.PublicKey().Encrypt(plainText)
	assert.Nil(t, err, "impl encrypt failed")

	decryptedText, err := privKey.Decrypt(cipherText)
	assert.Nil(t, err, "impl decrypt failed")
	assert.Equal(t, plainText, decryptedText, "impl decrypted text should equal")
}

// ToDo: Encrypt and Decrypt with tjfoc

// ToDo: sign and verify self

// ToDo: sign and verify with tjfoc
