package sm2_kms_test

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/stretchr/testify/assert"
	"github.com/tw-bc-group/gm-crypto-test-suite/kms/sm2_kms"
	"github.com/tw-bc-group/gm-crypto-test-suite/kms/sm2_kms/kms/tjfoc"
	"testing"
)

func initKMS() sm2_kms.Sm2KMS {
	// ToDo When Test: Replace your own sm2 kms
	//   that implements interface Sm2KMS
	return tjfoc.CreateKeyAdapter()
}

// TestGenerateKeyAndSavePem tests CreateKey() then
//   save pubKey to pem and read by tjfoc.
func TestCreateKeyAndSavePem(t *testing.T) {
	adapter := initKMS()
	assert.NotNil(t, adapter, "init failed")

	err := adapter.CreateKey()
	assert.Nil(t, err, "kms create key failed")
	pubKey := adapter.PublicKey()

	// kms key -> pem -> tjfoc key
	pubKeyPem, err := pubKey.WriteToPem()
	assert.Nil(t, err, "kms pub key write to pem failed")
	tjPubKey, err := x509.ReadPublicKeyFromPem(pubKeyPem)
	assert.Nil(t, err, "read pem from kms pub key failed")

	// tjfoc key -> pem -> new kms key
	tjPubKeyPem, err := x509.WritePublicKeyToPem(tjPubKey)
	assert.Nil(t, err, "tjfoc pub key write to pem failed")
	transformedPubKey, err := pubKey.ReadFromPem(tjPubKeyPem)
	assert.Nil(t, err, "kms pub key read from tjfoc failed")

	// compare new kms key with origin
	transformedPubKeyPem, err := transformedPubKey.WriteToPem()
	assert.Nil(t, err, "transformed kms pub key write to pem failed")
	assert.Equal(t, pubKeyPem, transformedPubKeyPem, "transformed kms should equal the origin one")
}

// TestSignAndVerify tests Sign() and Verify() methods
//   by kms self.
func TestSignAndVerify(t *testing.T) {
	adapter := initKMS()
	assert.NotNil(t, adapter, "init failed")

	err := adapter.CreateKey()
	assert.Nil(t, err, "kms create key failed")

	message := []byte("some message")
	signature, err := adapter.Sign(message)
	assert.Nil(t, err, "kms sign failed")

	res, err := adapter.Verify(message, signature)
	assert.Nil(t, err, "kms verify failed")
	assert.True(t, res, "kms verify should pass")

	err = adapter.DeleteKey()
	assert.Nil(t, err, "kms verify failed")
}

// TestSignAndVerify tests compatibility between kms and tjfoc
//   on Sign() and Verify() methods.
func TestSignAndVerifyCompatibility(t *testing.T) {
	adapter := initKMS()
	assert.NotNil(t, adapter, "init failed")

	err := adapter.CreateKey()
	assert.Nil(t, err, "kms create key failed")

	pubKey := adapter.PublicKey()
	pubKeyPem, _ := pubKey.WriteToPem()
	tjPubKey, _ := x509.ReadPublicKeyFromPem(pubKeyPem)

	// Sign by kms
	message := []byte("some message")
	signature, err := adapter.Sign(message)
	assert.Nil(t, err, "kms sign failed")

	// Verify by tjfoc
	res := tjPubKey.Verify(message, signature)
	assert.True(t, res, "tjfoc verify should pass")

	err = adapter.DeleteKey()
	assert.Nil(t, err, "kms verify failed")
}

// TestEncryptAndDecrypt tests Encrypt() and Decrypt()
//   methods by kms self.
func TestEncryptAndDecrypt(t *testing.T) {
	adapter := initKMS()
	assert.NotNil(t, adapter, "init failed")

	err := adapter.CreateKey()
	assert.Nil(t, err, "kms create key failed")

	plainText := []byte("plain text")
	cipherText, err := adapter.Encrypt(plainText)
	assert.Nil(t, err, "kms encrypt failed")

	decryptedText, err := adapter.Decrypt(cipherText)
	assert.Nil(t, err, "kms decrypt failed")
	assert.Equal(t, plainText, decryptedText, "kms decrypted text should equal")

	err = adapter.DeleteKey()
	assert.Nil(t, err, "kms verify failed")
}

// TestEncryptAndDecryptCompatibility tests compatibility
//   between kms and tjfoc on Encrypt() and Decrypt() methods.
func TestEncryptAndDecryptCompatibility(t *testing.T) {
	adapter := initKMS()
	assert.NotNil(t, adapter, "init failed")

	err := adapter.CreateKey()
	assert.Nil(t, err, "kms create key failed")

	plainText := []byte("plain text")
	pubKey := adapter.PublicKey()
	pubKeyPem, _ := pubKey.WriteToPem()
	tjPubKey, _ := x509.ReadPublicKeyFromPem(pubKeyPem)

	// Encrypt by tjfoc
	cipherText, _ := tjPubKey.EncryptAsn1(plainText, rand.Reader)

	// Decrypt by kms
	decryptedText, err := adapter.Decrypt(cipherText)
	assert.Nil(t, err, "tjfoc encrypted, kms decrypt failed")
	assert.Equal(t, plainText, decryptedText, "tjfoc encrypted, kms decrypted, text should equal")

	err = adapter.DeleteKey()
	assert.Nil(t, err, "kms verify failed")
}
