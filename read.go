package main

import (
	//"bufio"
	//"fmt"
	//"os"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
)

func NewCryptoReader(r io.Reader, strKey string) (c *CryptoPipe, err error) {
	npLog.Printf(1, "CALL NewCryptoReader(%p, [%s])\n", r, strKey)
	salt := make([]byte, 16)
	c = new(CryptoPipe)

	/* init values */
	c.init()

	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, 16384, 8, 1, 32)
	if err != nil {
		npLog.Printf(1, "RET NewCryptoReader(%p, [%s]) -> [Error:%s]\n", r, strKey, err.Error())
		return nil, err
	}

	copy(c.dKey[:], dKey)
	c.rd = r

	npLog.Printf(1, "RET NewCryptoReader(%p, [%s]) -> [c:%p]\n", r, strKey, c)
	return
}

// Read will read the amount of
func (c *CryptoPipe) Read(p []byte) (n int, err error) {
	npLog.Printf(1, "CALL (c:%p) Read(%p (%d))\n", c, p, cap(p))

	err = c.shazam()
	if err != nil {
		npLog.Printf(1, "PANIC (c:%p) Read(%p (%d)) -> [Error:%s]\n", c, p, cap(p), err.Error())
		panic(err)
	}

	b := make([]byte, len(p))
	//n, err = c.rd.Read(b)
	n, err = io.ReadFull(c.rd, b)
	if err != nil && err != io.ErrUnexpectedEOF {
		npLog.Printf(1, "RET (c:%p) Read(%p (%d)) -> [Error:%s]\n", c, p, cap(p), err.Error())
		return n, err
	}

	pt, res := secretbox.Open(nil, b[:n], c.cntNonce, c.dKey)
	if res == true {
		copy(p, pt)
		c.cnt++
		npLog.Printf(1, "RET (c:%p) Read(%p (%d)) -> %d, nil [PT:%s...]\n", c, p, cap(p), len(pt), hex.EncodeToString(pt)[:8])
		return len(pt), nil
	}
	npLog.Printf(1, "RET (c:%p) Read(%p (%d)) -> [Error:crypto error]\n", c, p, cap(p), err.Error)
	return 0, errors.New("crypto error")
}
