package sm2

import (
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestCreateKeyAndSavePubKeyPem tests CreateKey() then
//   save pubKey to pem and read by tjfoc.
func TestCreateKeyAndSavePubKeyPem(t *testing.T) {
	keyCreator := KeyCreator{}
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

// ToDo: Encrypt and Decrypt self

// ToDo: Encrypt and Decrypt with tjfoc

// ToDo: sign and verify self

// ToDo: sign and verify with tjfoc
