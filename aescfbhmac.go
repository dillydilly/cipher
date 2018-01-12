package mycipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"bytes"
	"os"
	"io"
	"fmt"

	"cyc10p5/myrand"
)

const (
	HMACSize	= 32
)

func EncryptAESCFB(key []byte, sf, df string) error {
	// open file to plaintext
	ptxt, err := os.Open(sf)
	if err != nil {
		return err
	}
	defer ptxt.Close()
	// get file size
	stat, err := ptxt.Stat()
	if err != nil {
		return err
	}
	ptxtSize := stat.Size()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// create buffer to send encoded ciphertext too
	var dst bytes.Buffer
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+ptxtSize)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(myrand.RandReader, iv); err != nil {
		return err
	}
	stream := cipher.NewCFBEncrypter(block, iv)

	// Grow the buffer to make room for everything
	dst.Grow(len(ciphertext))

	writer := &cipher.StreamWriter{S: stream, W: &dst}
	// Copy the input plaintxt to the output dst, encrypting as we go.
	if _, err := io.Copy(writer, ptxt); err != nil {
		return err
	}

	// get hmac of ciphertext and copy to end of ciphertext
	dst.Grow(HMACSize)
	csrc := dst.Bytes()[:]
	mac := hmac.New(sha256.New, key)
	mac.Write(csrc)
	dst.Write(mac.Sum(nil))

	// encode & write ciphertext+hmac to file
	ctxt, err := os.Create(df)
	if err != nil {
		return err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, ctxt)
	if _, err := io.Copy(encoder, &dst); err != nil {
		return err
	}
	encoder.Close()
	ctxt.Close()

	return nil
}

func checkMAC(ctxt, cmac, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(ctxt)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(cmac, expectedMAC)
}

func DecryptAESCFB(key []byte, sf, df string) error {
	ectxt, err := os.Open(sf)
	if err != nil {
		return err
	}
	// get file size
	stat, err := ectxt.Stat()
	if err != nil {
		return err
	}
	ectxtSize := int(stat.Size())
	// copy & decode ciphertext+hmac into buffer
	var cbuf bytes.Buffer
	cbuf.Grow(ectxtSize)
	fmt.Printf("buffer length: %s\n", cbuf.Len())
	decoder := base64.NewDecoder(base64.StdEncoding, ectxt)
	if _, err := io.Copy(&cbuf, decoder); err != nil {
		return err
	}
	ectxt.Close()

	// pull the IV from the ciphertext
	if cbuf.Len() < aes.BlockSize {
		fmt.Printf("ciphertext to short: %s\n", cbuf.Len())
		panic("Error: ciphertext to short...")
	}
	iv := cbuf.Bytes()[:aes.BlockSize]
	ciphertext := cbuf.Bytes()[aes.BlockSize:HMACSize]
	mac := cbuf.Bytes()[aes.BlockSize+len(ciphertext):]
	fmt.Printf("HMAC Length: %s\n", len(mac))

	// check for valid hmac
	if checkMAC(ciphertext, mac, key) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		stream := cipher.NewCFBDecrypter(block, iv)

		dst, err := os.OpenFile(df, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer dst.Close()

		reader := &cipher.StreamReader{S: stream, R: bytes.NewReader(ciphertext)}
		// Copy the input file to the output file, decrypting as we go.
		if _, err := io.Copy(dst, reader); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("hmac verify failure...\n")
	}
	return nil
}

