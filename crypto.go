// +build go1.10

package naclpipe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2" //let's add argon2id
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt" // let's keep scrypt
	"golang.org/x/crypto/sha3"
)

//
//
// INIT / INTERNAL
//
//
const (
	// PREVIOUS SCRYPT PARAMS
	oldScryptCostParam = 16384
	oldScryptCostN     = 8
	oldScryptCostP     = 1
	oldScryptKeyLen    = 32
	//oldScryptSaltLen   = 16

	// we increase scrypt params for configuration purposes
	scryptCostParam = 65536
	scryptCostN     = 16
	scryptCostP     = 4
	//scryptSaltLen   = 32
	//scryptSaltLen   = 16

	// our argon 2 parameters (we are in 2018)
	argonCostTime   = 2
	argonCostMemory = 256 * 1024
	argonCostThread = 8

	// generic
	keyLength     = 32
	SaltLength    = 32
	OldSaltLength = 16

	// we use argon 2id by default
	DerivateScrypt = iota
	DerivateArgon2id
	DerivateScrypt010
)

var (
	ErrUnsupported = errors.New("unsupported option")
	ErrUnsafe      = errors.New("unsafe option")
	ErrRead        = errors.New("read error")
	ErrWrite       = errors.New("write error")
)

type ScryptParams struct {
	CostParam int
	CostN     int
	CostP     int
	SaltLen   int
	KeyLength int
}

type Argon2Params struct {
	CostTime    uint32
	CostMemory  uint32
	CostThreads uint8
	KeyLength   uint32
}

// NaclPipe define the structure that handle the crypto pipe operation
// it also holds all internal datas related to the running pipe.
type NaclPipe struct {
	dKey     *[32]byte // derived key
	cntNonce *[24]byte
	cnt      uint64 // nonce counter
	salt     []byte // salt value mainly to avoid the writer writing before the first block is written.
	wr       io.Writer
	rd       io.Reader
	params   interface{}
	//stdioSize uint32
}

func (c *NaclPipe) initialize(d int) {
	c.cntNonce = new([24]byte)
	c.dKey = new([32]byte)
	c.cnt = 0
	c.salt = make([]byte, SaltLength)

	switch d {
	case DerivateScrypt010:
		c.params = ScryptParams{
			CostParam: oldScryptCostParam,
			CostN:     oldScryptCostN,
			CostP:     oldScryptCostP,
			SaltLen:   OldSaltLength,
			KeyLength: keyLength,
		}
		c.salt = make([]byte, OldSaltLength)
	case DerivateScrypt:
		c.params = ScryptParams{
			CostParam: scryptCostParam,
			CostN:     scryptCostN,
			CostP:     scryptCostP,
			SaltLen:   SaltLength,
			KeyLength: keyLength,
		}
	case DerivateArgon2id:
		fallthrough
	default:
		c.params = Argon2Params{
			CostTime:    argonCostTime,
			CostMemory:  argonCostMemory,
			CostThreads: argonCostThread,
			KeyLength:   keyLength,
		}
	}
}

// minimum password is 5 chars
func (c *NaclPipe) deriveKey(salt []byte, password string) (err error) {
	var dKey []byte

	// XXX TODO check salt is NOT all zero print a warning
	/*
		if len(password) < 5 || len(salt) < 12 {
			//fmt.Printf("password: %d salt: %d\n", len(password), len(salt))
			err = errUnsafe
			return
		}
	*/
	zero := make([]byte, len(salt))

	switch {
	case len(password) < 5:
		err = ErrUnsafe
		return
	case len(salt) < 12:
		err = ErrUnsafe
		return
	case bytes.Equal(zero, salt):
		err = ErrUnsafe
		return
	}

	switch v := c.params.(type) {
	case ScryptParams:
		/* let's derive a key */
		dKey, err = scrypt.Key([]byte(password), c.salt, v.CostParam, v.CostN, v.CostP, v.KeyLength)
		if err != nil {
			//npLog.Printf(1, "RET deriveKey( [%s]) -> [Error:%s]\n", strKey, err.Error())
			return
		}

	case Argon2Params:
		//fmt.Fprintf(os.Stderr, "ARGON DERIVATION\n")
		dKey = argon2.IDKey([]byte(password), c.salt, v.CostTime, v.CostMemory, v.CostThreads, v.KeyLength)
	default:
		err = ErrUnsupported
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

func (c *NaclPipe) initReader(r io.Reader, password string) (err error) {
	//c.salt = make([]byte, SaltLength)

	// we read the salt immediately
	_, err = r.Read(c.salt)
	if err != nil {
		return
	}

	/* let's derive a key */
	err = c.deriveKey(c.salt, password)
	if err != nil {
		return
	}
	c.rd = r
	return
}

func NewReader(r io.Reader, password string, derivation int) (io.Reader, error) {
	//npLog.Printf(1, "CALL NewReader(%p, [%s])\n", r, strKey)
	return newCryptoReader(r, password, derivation)
}

//func newCryptoReader(r io.Reader, strKey string, derivation int) (c *NaclPipe, err error) {
func newCryptoReader(r io.Reader, password string, derivation int) (io.Reader, error) {
	//npLog.Printf(1, "CALL newCryptoReader(%p, [%s])\n", r, strKey)
	//salt := make([]byte, 16)
	c := new(NaclPipe)

	/* init values/vars */
	c.initialize(derivation)

	/* let's derive a key */
	err := c.initReader(r, password)
	if err != nil {
		//npLog.Printf(1, "RET newCryptoReader(%p, [%s]) -> [Error:%s]\n", r, strKey, err.Error())
		return nil, err
	}
	//npLog.Printf(1, "RET newCryptoReader(%p, [%s]) -> [c:%p]\n", r, strKey, c)
	return c, nil
}

// Read will read the amount of
func (c *NaclPipe) Read(p []byte) (n int, err error) {
	//npLog.Printf(1, "CALL (c:%p) Read(%p (%d))\n", c, p, cap(p))
	if len(p) == 0 {
		return 0, nil
	}

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
	return 0, ErrRead
}

//
//
// WRITER
//
//

func (c *NaclPipe) writeSalt() (err error) {
	//npLog.Printf(1, "CALL (c:%p) WriteSalt(%p (%d))\n", c, c.salt, len(c.salt))
	n, err := c.wr.Write(c.salt)
	fmt.Printf("writeSalt(salt: %d bytes): n: %d err: %v\n", len(c.salt), n, err)
	return
}

func (c *NaclPipe) initWriter(w io.Writer, password string) (err error) {
	//c.salt = make([]byte, scryptSaltLen)

	// initialize a CSPRNG salt
	_, err = rand.Read(c.salt)
	if err != nil {
		return
	}

	/* let's derive a key */
	err = c.deriveKey(c.salt, password)
	if err != nil {
		return
	}

	c.wr = w
	return
}

func NewWriter(w io.Writer, password string, derivation int) (io.Writer, error) {
	//npLog.Printf(1, "CALL NewWriter(%p, [%s])\n", w, strKey)
	return newCryptoWriter(w, password, derivation)
}

//func newCryptoWriter(w io.Writer, strKey string, derivation int) (c *NaclPipe, err error) {
func newCryptoWriter(w io.Writer, password string, derivation int) (io.Writer, error) {
	//npLog.Printf(1, "CALL newCryptoWriter(%p, [%s])\n", w, strKey)
	//salt := make([]byte, 16)
	c := new(NaclPipe)

	/* init values/vars */
	c.initialize(derivation)

	/* let's derive a key */
	err := c.initWriter(w, password)
	if err != nil {
		//npLog.Printf(1, "RET newCryptoWriter(%p, [%s]) -> [Error: %s]\n", w, strKey, err.Error)
		return nil, err
	}

	//npLog.Printf(1, "RET newCryptoWriter(%p, [%s]) -> [c:%p]\n", w, strKey, c)
	return c, nil
}

// SHA3 the counter use it as nonce
func (c *NaclPipe) Write(p []byte) (n int, err error) {
	//npLog.Printf(1, "CALL (c:%p) Write(%p (%d))\n", c, p, len(p))

	c.shazam()

	if c.cnt == 0 {
		n, err = c.wr.Write(c.salt)
		//fmt.Printf("writeSalt(salt: %d bytes): n: %d err: %v\n", len(c.salt), n, err)
		//err = c.writeSalt()
		if err != nil {
			return
		}
	}

	// Seal
	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	c.cnt++

	// now Write()
	n, err = c.wr.Write(ct)
	if err != nil || n != len(ct) {
		fmt.Fprintf(os.Stderr, "we should write %d but wrote %d\n", len(ct), n)
	}
	//npLog.Printf(1, "RET (c:%p) Write(%p (%d)) -> %d, %v\n", c, p, len(p), n, err)
	n = len(p)
	return
}
