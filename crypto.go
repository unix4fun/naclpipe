// +build go1.7
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

//
//
// INIT / INTERNAL
//
//
const (
	scryptCostParam = 16384
	scryptCostN     = 8
	scryptCostP     = 1
	scryptKeyLen    = 32
)

// CryptoPipe define the structure that handle the crypto pipe operation
// it also holds all internal datas related to the running pipe.
type CryptoPipe struct {
	dKey      *[32]byte // derived key
	cntNonce  *[24]byte
	cnt       uint64 // nonce counter
	wr        io.Writer
	rd        io.Reader
	stdioSize uint32
}

func (c *CryptoPipe) InitZero() {
	c.cntNonce = new([24]byte)
	c.dKey = new([32]byte)
	c.cnt = 0
}

func (c *CryptoPipe) InitReader(r io.Reader, strKey string) (err error) {
	salt := make([]byte, 16)

	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, scryptCostParam, scryptCostN, scryptCostP, scryptKeyLen)
	if err != nil {
		npLog.Printf(1, "RET InitReader(%p, [%s]) -> [Error:%s]\n", r, strKey, err.Error())
		return err
	}

	copy(c.dKey[:], dKey)
	c.rd = r
	return
}

func (c *CryptoPipe) GetBufSize(size uint64) uint64 {
	switch {
	case c.wr != nil:
		return (size - secretbox.Overhead)
	default:
		return size
	}
}

func (c *CryptoPipe) InitWriter(w io.Writer, strKey string) (err error) {
	salt := make([]byte, 16)

	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, scryptCostParam, scryptCostN, scryptCostP, scryptKeyLen)
	if err != nil {
		npLog.Printf(1, "RET NewCryptoWriter(%p, [%s]) -> [Error: %s]\n", w, strKey, err.Error)
		return err
	}

	copy(c.dKey[:], dKey)
	c.wr = w
	return
}

// shazam function does an SHA3 on the counter and update the counter/Nonce value generated.
// stream operate in blocks, then each blocks will be encrypted with its nonce.
func (c *CryptoPipe) shazam() {
	npLog.Printf(1, "CALL (c:%p) shazam()\n", c)
	/*
		sha3hash := sha3.New256()
		countstr := fmt.Sprintf("%d", c.cnt)
		_, err = sha3hash.Write([]byte(countstr))
		if err != nil {
			npLog.Printf(1, "RET (c:%p) shazam() -> [Error: %s]\n", c, err.Error())
			return err
		}
		out := sha3hash.Sum(nil)
	*/
	out := sha3.Sum256([]byte(fmt.Sprintf("%d", c.cnt)))
	copy(c.cntNonce[:], out[:24])
	npLog.Printf(1, "RET (c:%p) shazam() -> [Counter: %d Nonce: %x Sha3: %x]\n", c, c.cnt, c.cntNonce, out)
	return
}

//
//
// READER
//
//

func NewCryptoReader(r io.Reader, strKey string) (c *CryptoPipe, err error) {
	npLog.Printf(1, "CALL NewCryptoReader(%p, [%s])\n", r, strKey)
	//salt := make([]byte, 16)
	c = new(CryptoPipe)

	/* init values */
	c.InitZero()

	/* let's derive a key */
	err = c.InitReader(r, strKey)
	if err != nil {
		npLog.Printf(1, "RET NewCryptoReader(%p, [%s]) -> [Error:%s]\n", r, strKey, err.Error())
		return nil, err
	}
	npLog.Printf(1, "RET NewCryptoReader(%p, [%s]) -> [c:%p]\n", r, strKey, c)
	return
}

// Read will read the amount of
func (c *CryptoPipe) Read(p []byte) (n int, err error) {
	npLog.Printf(1, "CALL (c:%p) Read(%p (%d))\n", c, p, cap(p))

	c.shazam()

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

//
//
// WRITER
//
//

func NewCryptoWriter(w io.Writer, strKey string) (c *CryptoPipe, err error) {
	npLog.Printf(1, "CALL NewCryptoWriter(%p, [%s])\n", w, strKey)
	//salt := make([]byte, 16)
	c = new(CryptoPipe)

	/* init values */
	c.InitZero()

	/* let's derive a key */
	err = c.InitWriter(w, strKey)
	if err != nil {
		npLog.Printf(1, "RET NewCryptoWriter(%p, [%s]) -> [Error: %s]\n", w, strKey, err.Error)
		return nil, err
	}

	npLog.Printf(1, "RET NewCryptoWriter(%p, [%s]) -> [c:%p]\n", w, strKey, c)
	return
}

// SHA3 the counter use it as nonce
func (c *CryptoPipe) Write(p []byte) (n int, err error) {
	npLog.Printf(1, "CALL (c:%p) Write(%p (%d))\n", c, p, len(p))

	c.shazam()
	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	c.cnt++
	//fmt.Fprintf(os.Stderr, "BOX HEX[%d]: %s\n", len(ct), hex.EncodeToString(ct)[:32])
	n, err = c.wr.Write(ct)

	npLog.Printf(1, "RET (c:%p) Write(%p (%d)) -> %d, %v\n", c, p, len(p), n, err)
	return
}
