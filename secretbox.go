// Package secretbox encrypts and authenticates small messages.
// Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate messages
// with secret-key cryptography. The length of messages is not hidden.
package cipher

import (
	"io"
	"log"
	"unsafe"

	"github.com/awnumar/memguard"
	myrand "github.com/dillydilly/rand"
	"golang.org/x/crypto/nacl/secretbox"
)

func EncryptSbox(key *memguard.LockedBuffer, msg []byte) ([]byte, error) {
	// test key length, should 32[]bytes
	if key.Size() != 32 {
		log.Printf("EncryptSecretbox:Wrong key length: %v", key.Size())
		memguard.SafeExit(1)
	}
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(myrand.RandReader, nonce[:]); err != nil {
		log.Printf("Error: %v\n", err)
		memguard.SafeExit(1)
	}
	// This encrypts msg and appends the result to the nonce.
	//var secretKey [32]byte
	//copy(secretKey[:], key)
	// Get the key as an array.
	keyArrayPtr := (*[32]byte)(unsafe.Pointer(&key.Buffer()[0]))

	encrypted := secretbox.Seal(nonce[:], msg, &nonce, keyArrayPtr)
	return encrypted, nil
}

func DecryptSbox(key *memguard.LockedBuffer, emsg []byte) ([]byte, error) {
	// check key length
	if key.Size() != 32 {
		log.Printf("DecryptSecretbox:Wrong key length: %v", key.Size())
		memguard.SafeExit(1)
	}
	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. Above, we stored the nonce in the first
	// 24 bytes of the encrypted text.
	var decryptNonce [24]byte
	copy(decryptNonce[:], emsg[:24])
	//var secretKey [32]byte
	//copy(secretKey[:], key)
	// Get the key as an array.
	keyArrayPtr := (*[32]byte)(unsafe.Pointer(&key.Buffer()[0]))

	decrypted, ok := secretbox.Open(nil, emsg[24:], &decryptNonce, keyArrayPtr)
	if !ok {
		log.Println("Secretbox Decrypt err...", ok)
		memguard.SafeExit(1)
	}
	return decrypted, nil
}
