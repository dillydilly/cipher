package mycipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"

	"github.com/awnumar/memguard"
	myrand "github.com/dillydilly/rand"
)

/*
Encrypted messages are prefixed with an encryptionVersion byte
that is used for us to be able to properly encode/decode. We
currently support the following versions:
 0 - AES-GCM 256, using PKCS7 padding
 1 - AES-GCM 256, no padding. Padding not needed, caused bloat.
*/
type encryptionVersion uint8

const (
	minEncryptionVersion encryptionVersion = 0
	maxEncryptionVersion encryptionVersion = 1
)

const (
	versionSize    = 1
	nonceSize      = 12
	tagSize        = 16
	maxPadOverhead = 16
	blockSize      = aes.BlockSize
)

// pkcs7encode is used to pad a byte buffer to a specific block size using
// the PKCS7 algorithm. "Ignores" some bytes to compensate for IV
func pkcs7encode(buf *bytes.Buffer, ignore, blockSize int) {
	n := buf.Len() - ignore
	more := blockSize - (n % blockSize)
	for i := 0; i < more; i++ {
		buf.WriteByte(byte(more))
	}
}

// pkcs7decode is used to decode a buffer that has been padded
func pkcs7decode(buf []byte, blockSize int) []byte {
	if len(buf) == 0 {
		panic("Cannot decode a PKCS7 buffer of zero length")
	}
	n := len(buf)
	last := buf[n-1]
	n -= int(last)
	return buf[:n]
}

// encryptOverhead returns the maximum possible overhead of encryption by version
func encryptOverhead(vsn encryptionVersion) int {
	switch vsn {
	case 0:
		return 45 // Version: 1, IV: 12, Padding: 16, Tag: 16
	case 1:
		return 29 // Version: 1, IV: 12, Tag: 16
	default:
		panic("unsupported version")
	}
}

// encryptedLength is used to compute the buffer size needed
// for a message of given length
func encryptedLength(vsn encryptionVersion, inp int) int {
	// If we are on version 1, there is no padding
	if vsn >= 1 {
		return versionSize + nonceSize + inp + tagSize
	}

	// Determine the padding size
	padding := blockSize - (inp % blockSize)

	// Sum the extra parts to get total size
	return versionSize + nonceSize + inp + padding + tagSize
}

// encryptPayload is used to encrypt a message with a given key.
// We make use of AES-256 in GCM mode. New byte buffer is the version,
// nonce, ciphertext and tag
func EncryptAESGCM(vsn encryptionVersion, key *memguard.LockedBuffer, msg, adata []byte, dst *bytes.Buffer) error {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	// make sure key is correct length
	if len(key.Buffer()) != 32 {
		return fmt.Errorf("EncryptAESGCM:Wrong key length: %v", len(key.Buffer()))
	}

	// Get the key as an array.
	//keyArrayPtr := (*[32]byte)(unsafe.Pointer(&key.Buffer[0]))
	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key.Buffer())
	if err != nil {
		fmt.Println("aes.NewCipher error: %v\n", err)
		return err
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println("cipher.NewGCM error: %v\n", err)
		return err
	}

	// Grow the buffer to make room for everything
	offset := dst.Len()
	dst.Grow(encryptedLength(vsn, len(msg)))

	// Write the encryption version
	dst.WriteByte(byte(vsn))

	// Add a random nonce
	io.CopyN(dst, myrand.RandReader, nonceSize)
	afterNonce := dst.Len()

	// Ensure we are correctly padded (only version 0)
	if vsn == 0 {
		io.Copy(dst, bytes.NewReader(msg))
		pkcs7encode(dst, offset+versionSize+nonceSize, aes.BlockSize)
	}

	// Encrypt message using GCM
	slice := dst.Bytes()[offset:]
	nonce := slice[versionSize : versionSize+nonceSize]

	// Message source depends on the encryption version.
	// Version 0 uses padding, version 1 does not
	var src []byte
	if vsn == 0 {
		src = slice[versionSize+nonceSize:]
	} else {
		src = msg
	}
	out := gcm.Seal(nil, nonce, src, adata)

	// Truncate the plaintext, and write the cipher text
	dst.Truncate(afterNonce)
	dst.Write(out)
	return nil
}

// decryptMessage performs the actual decryption of ciphertext. This is in its
// own function to allow it to be called on all keys easily.
func decryptMessage(msg, adata []byte, key *memguard.LockedBuffer) ([]byte, error) {
	// Get the key as an array.
	//keyArrayPtr := (*[32]byte)(unsafe.Pointer(&key.Buffer[0]))

	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key.Buffer())
	if err != nil {
		log.Printf("decryptMessage:aes.NewCipher: %v\n", err)
		memguard.SafeExit(1)
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Printf("decryptMessage:cipher.NewGCM: %v\n", err)
		memguard.SafeExit(1)
	}

	// Decrypt the message
	nonce := msg[versionSize : versionSize+nonceSize]
	ciphertext := msg[versionSize+nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, adata)
	if err != nil {
		log.Printf("decryptMessage:gcm.Open: %v\n", err)
		memguard.SafeExit(1)
	}
	// Success!
	return plain, nil
}

// decryptPayload is used to decrypt a message with a given key,
// and verify it's contents. Any padding will be removed, and a
// slice to the plaintext is returned. Decryption is done IN PLACE!
func DecryptAESGCM(msg, adata []byte, key *memguard.LockedBuffer) ([]byte, error) {
	// Ensure we have at least one byte
	if len(msg) == 0 {
		log.Println("DecryptAESGCM: Cannot decrypt empty payload")
		memguard.SafeExit(1)
	}
	// Verify the version
	vsn := encryptionVersion(msg[0])
	if vsn > maxEncryptionVersion {
		log.Printf("DecryptAESGCM: Unsupported encryption version %d", msg[0])
		memguard.SafeExit(1)
	}
	// Ensure the length is sane
	if len(msg) < encryptedLength(vsn, 0) {
		log.Printf("DecryptAESGCM: Payload is too small to decrypt: %d", len(msg))
		memguard.SafeExit(1)
	}
	plain, err := decryptMessage(msg, adata, key)
	if err == nil {
		// Remove the PKCS7 padding for vsn 0
		if vsn == 0 {
			return pkcs7decode(plain, aes.BlockSize), nil
		} else {
			return plain, nil
		}
	} else {
		log.Printf("DecryptAESGCM Error: %v\n", err)
		memguard.SafeExit(1)
	}

	return nil, fmt.Errorf("DecryptAESGCM: Wrong key, unable to decrypt: %s\n", err)
}
