package sm2_impl_test

import (
	"github.com/stretchr/testify/assert"
	"github.com/tw-bc-group/gm-crypto-test-suite/implement/sm2_impl"
	"github.com/tw-bc-group/gm-crypto-test-suite/implement/sm2_impl/impl/tjfoc"
	"testing"
)

func initImplA() sm2_impl.Sm2Creator {
	// ToDo When Test: Replace your own sm2 implement A
	//   that implements interface Sm2Creator
	return &tjfoc.KeyCreator{}
}

func initImplB() sm2_impl.Sm2Creator {
	// ToDo When Test: Replace your own sm2 implement B
	//   that implements interface Sm2Creator
	return &tjfoc.KeyCreator{}
}

// TestCreateKeyAndSavePubKeyPem tests CreateKey() then
//   save pubKey to pem and read it.
func TestCreateKeyAndSavePubKeyPem(t *testing.T) {
	keyCreatorA := initImplA()
	pubKeyA := keyCreatorA.CreateKey().PublicKey()
	assert.NotNil(t, pubKeyA, "init failed")
	keyCreatorB := initImplB()
	pubKeyB := keyCreatorB.CreateKey().PublicKey()
	assert.NotNil(t, pubKeyB, "init failed")

	// pub key A -> pem -> pub key B
	pubKeyPemA, err := pubKeyA.WriteToPem()
	assert.Nil(t, err, "pub key A write to pem failed")
	pubKeyA2B, err := pubKeyB.ReadFromPem(pubKeyPemA)
	assert.Nil(t, err, "read pem from pub key A failed")

	// pub key B -> pem -> new pub key A
	pubKeyPemA2B, err := pubKeyA2B.WriteToPem()
	assert.Nil(t, err, "pub key B write to pem failed")
	pubKeyA2B2A, err := pubKeyA.ReadFromPem(pubKeyPemA2B)
	assert.Nil(t, err, "pub key A read from B failed")

	// compare new pub key A with origin
	pubKeyPemA2B2A, err := pubKeyA2B2A.WriteToPem()
	assert.Nil(t, err, "pub key A write to pem failed")
	assert.Equal(t, pubKeyPemA, pubKeyPemA2B2A, "new pub key A should equal the origin one")
}

// TestCreateKeyAndSavePrivKeyPem tests CreateKey() then
//   save privKey to pem and read it.
func TestCreateKeyAndSavePrivKeyPem(t *testing.T) {
	keyCreatorA := initImplA()
	privKeyA := keyCreatorA.CreateKey()
	assert.NotNil(t, privKeyA, "init failed")
	keyCreatorB := initImplB()
	privKeyB := keyCreatorB.CreateKey()
	assert.NotNil(t, privKeyB, "init failed")

	// priv key A -> pem -> priv key B
	privKeyPemA, err := privKeyA.WriteToPem()
	assert.Nil(t, err, "priv key A write to pem failed")
	privKeyA2B, err := privKeyB.ReadFromPem(privKeyPemA)
	assert.Nil(t, err, "read pem from priv key A failed")

	// priv key B -> pem -> new priv key A
	privKeyPemA2B, err := privKeyA2B.WriteToPem()
	assert.Nil(t, err, "priv key B write to pem failed")
	privKeyA2B2A, err := privKeyA.ReadFromPem(privKeyPemA2B)
	assert.Nil(t, err, "priv key A read from B failed")

	// compare new priv key A with origin
	privKeyPemA2B2A, err := privKeyA2B2A.WriteToPem()
	assert.Nil(t, err, "new priv key A write to pem failed")
	assert.Equal(t, privKeyPemA, privKeyPemA2B2A, "new priv key A should equal the origin one")
}

// TestEncryptAndDecryptCompatibility tests compatibility between Alice and Bob
//   on Encrypt() and Decrypt() methods.
func TestEncryptAndDecryptCompatibility(t *testing.T) {
	testParameters := []struct {
		alice sm2_impl.Sm2Creator
		bob   sm2_impl.Sm2Creator
	}{
		{initImplA(), initImplB()},
		{initImplB(), initImplA()},
	}
	for _, parameter := range testParameters {
		keyCreatorAlice := parameter.alice
		keyCreatorBob := parameter.bob

		// Bob create key
		privKeyBob := keyCreatorBob.CreateKey()
		pubKeyPemBob, _ := privKeyBob.PublicKey().WriteToPem()
		pubKeyTarget, _ := keyCreatorAlice.CreateKey().PublicKey().ReadFromPem(pubKeyPemBob)

		// Encrypt by Alice
		plainText := []byte("plain text")
		cipherText, err := pubKeyTarget.Encrypt(plainText)
		assert.Nil(t, err, "alice encrypt failed")

		// Decrypt by Bob
		decryptedText, err := privKeyBob.Decrypt(cipherText)
		assert.Nil(t, err, "bob decrypt failed")
		assert.Equal(t, plainText, decryptedText, "alice encrypted, bob decrypted, text should equal")
	}
}

// TestSignAndVerifyCompatibility tests compatibility between Alice and Bob
//   on Sign() and Verify() methods.
func TestSignAndVerifyCompatibility(t *testing.T) {
	testParameters := []struct {
		alice sm2_impl.Sm2Creator
		bob   sm2_impl.Sm2Creator
	}{
		{initImplA(), initImplB()},
		{initImplB(), initImplA()},
	}
	for _, parameter := range testParameters {
		keyCreatorAlice := parameter.alice
		keyCreatorBob := parameter.bob

		// Alice create key
		privKeyAlice := keyCreatorAlice.CreateKey()
		pubKeyPemAlice, _ := privKeyAlice.PublicKey().WriteToPem()
		pubKeyBob, _ := keyCreatorBob.CreateKey().PublicKey().ReadFromPem(pubKeyPemAlice)

		// Sign by Alice
		message := []byte("some message")
		signature, err := privKeyAlice.Sign(message)
		assert.Nil(t, err, "Alice sign failed")

		// Verify by bob
		res, err := pubKeyBob.Verify(message, signature)
		assert.Nil(t, err, "Bob verify failed")
		assert.True(t, res, "Bob verify should pass")
	}
}
