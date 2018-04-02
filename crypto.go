// +build go1.7
package naclpipe

import (
	"crypto/rand"
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
	scryptSaltLen   = 16
)

// NaclPipe define the structure that handle the crypto pipe operation
// it also holds all internal datas related to the running pipe.
type NaclPipe struct {
	dKey      *[32]byte // derived key
	cntNonce  *[24]byte
	cnt       uint64 // nonce counter
	salt      []byte // salt value mainly to avoid the writer writing before the first block is written.
	wr        io.Writer
	rd        io.Reader
	stdioSize uint32
}

func (c *NaclPipe) initialize() {
	c.cntNonce = new([24]byte)
	c.dKey = new([32]byte)
	c.cnt = 0
}

func (c *NaclPipe) deriveKey(salt []byte, strKey string) (err error) {
	/* let's derive a key */
	dKey, err := scrypt.Key([]byte(strKey), salt, scryptCostParam, scryptCostN, scryptCostP, scryptKeyLen)
	if err != nil {
		//npLog.Printf(1, "RET deriveKey( [%s]) -> [Error:%s]\n", strKey, err.Error())
		return
	}

	copy(c.dKey[:], dKey)
	return
}

func (c *NaclPipe) GetBufSize(size uint64) uint64 {
	switch {
	case c.wr != nil:
		return (size - secretbox.Overhead)
	default:
		return size
	}
}

// shazam function does an SHA3 on the counter and update the counter/Nonce value generated.
// stream operate in blocks, then each blocks will be encrypted with its nonce.
func (c *NaclPipe) shazam() {
	//npLog.Printf(1, "CALL (c:%p) shazam()\n", c)
	out := sha3.Sum256([]byte(fmt.Sprintf("%d", c.cnt)))
	copy(c.cntNonce[:], out[:24])
	//npLog.Printf(1, "RET (c:%p) shazam() -> [Counter: %d Nonce: %x Sha3: %x]\n", c, c.cnt, c.cntNonce, out)
	return
}

//
//
// READER
//
//

func (c *NaclPipe) initReader(r io.Reader, strKey string) (err error) {
	salt := make([]byte, scryptSaltLen)

	// we read the salt immediately
	_, err = r.Read(salt)
	if err != nil {
		return err
	}

	/* let's derive a key */
	err = c.deriveKey(salt, strKey)
	if err != nil {
		return
	}
	c.rd = r
	return
}

func NewReader(r io.Reader, strKey string) (io.Reader, error) {
	//npLog.Printf(1, "CALL NewReader(%p, [%s])\n", r, strKey)
	return newCryptoReader(r, strKey)
}

func newCryptoReader(r io.Reader, strKey string) (c *NaclPipe, err error) {
	//npLog.Printf(1, "CALL newCryptoReader(%p, [%s])\n", r, strKey)
	//salt := make([]byte, 16)
	c = new(NaclPipe)

	/* init values */
	c.initialize()

	/* let's derive a key */
	err = c.initReader(r, strKey)
	if err != nil {
		//npLog.Printf(1, "RET newCryptoReader(%p, [%s]) -> [Error:%s]\n", r, strKey, err.Error())
		return nil, err
	}
	//npLog.Printf(1, "RET newCryptoReader(%p, [%s]) -> [c:%p]\n", r, strKey, c)
	return
}

// Read will read the amount of
func (c *NaclPipe) Read(p []byte) (n int, err error) {
	//npLog.Printf(1, "CALL (c:%p) Read(%p (%d))\n", c, p, cap(p))

	c.shazam()

	//b := make([]byte, len(p))
	b := make([]byte, len(p)+secretbox.Overhead)

	//n, err = c.rd.Read(b)
	n, err = io.ReadFull(c.rd, b)
	if err != nil && err != io.ErrUnexpectedEOF {
		//npLog.Printf(1, "RET (c:%p) Read(%p (%d)) -> [Error:%s]\n", c, p, cap(p), err.Error())
		return n, err
	}

	pt, res := secretbox.Open(nil, b[:n], c.cntNonce, c.dKey)
	if res == true {
		copy(p, pt)
		c.cnt++
		return len(pt), nil
	}
	//npLog.Printf(1, "RET (c:%p) Read(%p (%d)) -> [Error:crypto error]\n", c, p, cap(p), err.Error)
	return 0, errors.New("secretbox.Open() error")
}

//
//
// WRITER
//
//

func (c *NaclPipe) writeSalt() (err error) {
	//npLog.Printf(1, "CALL (c:%p) WriteSalt(%p (%d))\n", c, c.salt, len(c.salt))
	_, err = c.wr.Write(c.salt)
	return
}

func (c *NaclPipe) initWriter(w io.Writer, strKey string) (err error) {
	c.salt = make([]byte, scryptSaltLen)
	// initialize a CSPRNG salt
	_, err = rand.Read(c.salt)
	if err != nil {
		return
	}

	/* let's derive a key */
	err = c.deriveKey(c.salt, strKey)
	if err != nil {
		return
	}

	c.wr = w
	return
}

func NewWriter(w io.Writer, strKey string) (io.Writer, error) {
	//npLog.Printf(1, "CALL NewWriter(%p, [%s])\n", w, strKey)
	return newCryptoWriter(w, strKey)
}

func newCryptoWriter(w io.Writer, strKey string) (c *NaclPipe, err error) {
	//npLog.Printf(1, "CALL newCryptoWriter(%p, [%s])\n", w, strKey)
	//salt := make([]byte, 16)
	c = new(NaclPipe)

	/* init values */
	c.initialize()

	/* let's derive a key */
	err = c.initWriter(w, strKey)
	if err != nil {
		//npLog.Printf(1, "RET newCryptoWriter(%p, [%s]) -> [Error: %s]\n", w, strKey, err.Error)
		return nil, err
	}

	//npLog.Printf(1, "RET newCryptoWriter(%p, [%s]) -> [c:%p]\n", w, strKey, c)
	return
}

// SHA3 the counter use it as nonce
func (c *NaclPipe) Write(p []byte) (n int, err error) {
	//npLog.Printf(1, "CALL (c:%p) Write(%p (%d))\n", c, p, len(p))

	c.shazam()

	if c.cnt == 0 {
		err = c.writeSalt()
		if err != nil {
			return
		}
	}

	// Seal
	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	c.cnt++

	// now Write()
	n, err = c.wr.Write(ct)
	//npLog.Printf(1, "RET (c:%p) Write(%p (%d)) -> %d, %v\n", c, p, len(p), n, err)
	return
}
