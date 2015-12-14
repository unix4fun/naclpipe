package main

import (
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	//"fmt"
	//"encoding/hex"
	//"os"
)

func NewCryptoWriter(w io.Writer, strKey string) (c *CryptoPipe, err error) {
	salt := make([]byte, 16)
	c = new(CryptoPipe)

	/* init values */
	c.init()

	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	copy(c.dKey[:], dKey)
	c.wr = w
	return
}

// SHA3 the counter use it as nonce
func (c *CryptoPipe) Write(p []byte) (n int, err error) {
	err = c.shazam()
	if err != nil {
		panic(err)
	}

	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	c.cnt++
	//fmt.Fprintf(os.Stderr, "BOX HEX[%d]: %s\n", len(ct), hex.EncodeToString(ct)[:32])
	return c.wr.Write(ct)
}
