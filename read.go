package main

import (
	//"bufio"
	//"encoding/hex"
	//"fmt"
	//"os"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
)

func NewCryptoReader(r io.Reader, strKey string) (c *CryptoPipe, err error) {
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
	c.rd = r

	return
}

// Read will read the amount of
func (c *CryptoPipe) Read(p []byte) (n int, err error) {
	//fmt.Fprintf(os.Stderr, "CRYPTO READ: %d\n", len(p))

	err = c.shazam()
	if err != nil {
		panic(err)
	}

	//fmt.Fprintf(os.Stderr, "CRYPTO READ PT: %d - %d\n", len(p), secretbox.Overhead)
	b := make([]byte, len(p))
	//n, err = c.rd.Read(b)
	n, err = io.ReadFull(c.rd, b)
	//fmt.Fprintf(os.Stderr, "(%v) BOX HEX[%d/%d]: %s\n", err, len(b), n, hex.EncodeToString(b)[:32])
	if err != nil && err != io.ErrUnexpectedEOF {
		return n, err
	}

	pt, res := secretbox.Open(nil, b[:n], c.cntNonce, c.dKey)
	if res == true {
		copy(p, pt)
		c.cnt++
		return len(pt), nil
	}
	return 0, errors.New("crypto error")
}
