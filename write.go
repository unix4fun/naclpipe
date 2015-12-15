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
	npLog.Printf(1, "CALL NewCryptoWriter(%p, [%s])\n", w, strKey)
	salt := make([]byte, 16)
	c = new(CryptoPipe)

	/* init values */
	c.init()

	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, 16384, 8, 1, 32)
	if err != nil {
		npLog.Printf(1, "RET NewCryptoWriter(%p, [%s]) -> [Error: %s]\n", w, strKey, err.Error)
		return nil, err
	}

	copy(c.dKey[:], dKey)
	c.wr = w
	npLog.Printf(1, "RET NewCryptoWriter(%p, [%s]) -> [c:%p]\n", w, strKey, c)
	return
}

// SHA3 the counter use it as nonce
func (c *CryptoPipe) Write(p []byte) (n int, err error) {
	npLog.Printf(1, "CALL (c:%p) Write(%p (%d))\n", c, p, len(p))
	err = c.shazam()
	if err != nil {
		npLog.Printf(1, "PANIC (c:%p) Write(%p (%d)) -> [Error: %s]\n", c, p, len(p), err.Error())
		panic(err)
	}

	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	c.cnt++
	//fmt.Fprintf(os.Stderr, "BOX HEX[%d]: %s\n", len(ct), hex.EncodeToString(ct)[:32])
	n, err = c.wr.Write(ct)
	npLog.Printf(1, "RET (c:%p) Write(%p (%d)) -> %d, %v\n", c, p, len(p), n, err)
	return
}
