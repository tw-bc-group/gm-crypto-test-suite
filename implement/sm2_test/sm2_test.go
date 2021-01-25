package sm2

import (
	"crypto/rand"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
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

// TestCreateKeyAndSavePrivKeyPem tests CreateKey() then
//   save privKey to pem and read by tjfoc.
func TestCreateKeyAndSavePrivKeyPem(t *testing.T) {
	keyCreator := initImpl()
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")

	// kms key -> pem -> tjfoc key
	privKeyPem, err := privKey.WriteToPem()
	assert.Nil(t, err, "kms pub key write to pem failed")
	tjPrivKey, err := x509.ReadPrivateKeyFromPem(privKeyPem, nil)
	assert.Nil(t, err, "read pem from kms pub key failed")

	// tjfoc key -> pem -> new kms key
	tjPrivKeyPem, err := x509.WritePrivateKeyToPem(tjPrivKey, nil)
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
	keyCreator := initImpl()
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")

	plainText := []byte("plain text")
	cipherText, err := privKey.PublicKey().Encrypt(plainText)
	assert.Nil(t, err, "impl encrypt failed")

	decryptedText, err := privKey.Decrypt(cipherText)
	assert.Nil(t, err, "impl decrypt failed")
	assert.Equal(t, plainText, decryptedText, "impl decrypted text should equal")
}

func TestEncryptAndDecryptCompatibility(t *testing.T) {
	t.Run("Impl Encrypt Then Base Decrypt", TestImplEncryptThenBaseDecrypt)
	t.Run("Base Encrypt Then Impl Decrypt", TestBaseEncryptThenImplDecrypt)
}

func TestImplEncryptThenBaseDecrypt(t *testing.T) {
	// base create key
	privKey, _ := sm2.GenerateKey(nil)
	pubKeyPem, _ := x509.WritePublicKeyToPem(&privKey.PublicKey)
	implPubKey, _ := initImpl().CreateKey().PublicKey().ReadFromPem(pubKeyPem)

	// Encrypt by impl
	plainText := []byte("plain text")
	cipherText, err := implPubKey.Encrypt(plainText)
	assert.Nil(t, err, "impl encrypt failed")

	// Decrypt by base
	decryptedText, err := privKey.DecryptAsn1(cipherText)
	assert.Nil(t, err, "base decrypt failed")
	assert.Equal(t, plainText, decryptedText, "impl encrypted, base decrypted, text should equal")
}

func TestBaseEncryptThenImplDecrypt(t *testing.T) {
	// impl create key
	keyCreator := initImpl()
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")
	pubKeyPem, _ := privKey.PublicKey().WriteToPem()
	basePubKey, _ := x509.ReadPublicKeyFromPem(pubKeyPem)

	// Encrypt by base
	plainText := []byte("plain text")
	cipherText, err := basePubKey.EncryptAsn1(plainText, rand.Reader)
	assert.Nil(t, err, "base encrypt failed")

	// Decrypt by impl
	decryptedText, err := privKey.Decrypt(cipherText)
	assert.Nil(t, err, "impl decrypt failed")
	assert.Equal(t, plainText, decryptedText, "base encrypted, impl decrypted, text should equal")
}

// TestSignAndVerify tests Sign() and Verify()
//   methods by impl self
func TestSignAndVerify(t *testing.T) {
	keyCreator := initImpl()
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")

	message := []byte("some message")
	signature, err := privKey.Sign(message)
	assert.Nil(t, err, "impl sign failed")

	res, err := privKey.PublicKey().Verify(message, signature)
	assert.Nil(t, err, "impl verify failed")
	assert.True(t, res, "impl verify should pass")
}

// TestSignAndVerifyCompatibility tests compatibility between impl and base
//   on Sign() and Verify() methods.
func TestSignAndVerifyCompatibility(t *testing.T) {
	t.Run("Impl Sign And Base Verify", TestImplSignAndBaseVerify)
	t.Run("Base Sign And Impl Verify", TestBaseSignAndImplVerify)
}

func TestImplSignAndBaseVerify(t *testing.T) {
	// impl create key
	keyCreator := initImpl()
	privKey := keyCreator.CreateKey()
	assert.NotNil(t, privKey, "init failed")
	pubKeyPem, _ := privKey.PublicKey().WriteToPem()
	tjPubKey, _ := x509.ReadPublicKeyFromPem(pubKeyPem)

	// Sign by impl
	message := []byte("some message")
	signature, err := privKey.Sign(message)
	assert.Nil(t, err, "impl sign failed")

	// Verify by base
	res := tjPubKey.Verify(message, signature)
	assert.True(t, res, "base verify should pass")
}

func TestBaseSignAndImplVerify(t *testing.T) {
	// base create key
	privKey, _ := sm2.GenerateKey(nil)
	pubKeyPem, _ := x509.WritePublicKeyToPem(&privKey.PublicKey)
	implPubKey, _ := initImpl().CreateKey().PublicKey().ReadFromPem(pubKeyPem)

	// Sign by base
	message := []byte("some message")
	signature, _ := privKey.Sign(rand.Reader, message, nil)

	// Verify by impl
	res, err := implPubKey.Verify(message, signature)
	assert.Nil(t, err, "impl verify failed")
	assert.True(t, res, "impl verify should pass")
}
