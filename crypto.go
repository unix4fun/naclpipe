// +build go1.10

// Copyright 2016-2018 (c) Eric "eau" Augé <eau+naclpipe@unix4fun.net>
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation and/or
// other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package naclpipe provides io.Reader / io.Writer compatible crypto interface
// it is possible to create a transparent crypto interface on top of an
// io.Reader/io.Writer pattern.
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
	// we increase scrypt params for configuration purposes
	scryptCostParam = 65536
	scryptCostN     = 16
	scryptCostP     = 4

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
)

var (
	// ErrUnsupported triggers for using an unsupported derivation function.
	ErrUnsupported = errors.New("unsupported option")
	// ErrUnsafe triggers for unsafe key derivation function.
	ErrUnsafe = errors.New("unsafe option")
	// ErrRead triggers on an error from the underlying io.Reader
	ErrRead = errors.New("read error")
	// ErrWrite triggers on an error from the underlying io.Writer
	ErrWrite = errors.New("write error")
)

// ScryptParams describes the parameters used for calling the scrypt key derivation function.
type ScryptParams struct {
	CostParam int
	CostN     int
	CostP     int
	SaltLen   int
	KeyLength int
}

// Argon2Params describes the parameters used for calling the Argon2id key derivation function.
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

// initialize the params
func (c *NaclPipe) initialize(d int) {
	c.cntNonce = new([24]byte)
	c.dKey = new([32]byte)
	c.cnt = 0
	c.salt = make([]byte, SaltLength)

	switch d {
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

// key derivation wrapper call
func (c *NaclPipe) deriveKey(salt []byte, password string) (err error) {
	var dKey []byte

	// check salt is NOT all zero print a warning
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

// shazam function does an SHA3 on the counter and update the counter/Nonce value generated.
// stream operate in blocks, then each blocks will be encrypted with its nonce.
func (c *NaclPipe) shazam() {
	out := sha3.Sum256([]byte(fmt.Sprintf("%d", c.cnt)))
	copy(c.cntNonce[:], out[:24])
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

// NewReader initialize an io.Reader using 'password' and the selected derivation function.
// Example:
//	cryptoReader, err := naclpipe.NewReader(os.Stdin, "mypassword", naclpipe.DerivateScrypt)
//	if err != nil {
//		return err
//	}
func NewReader(r io.Reader, password string, derivation int) (io.Reader, error) {
	return newCryptoReader(r, password, derivation)
}

//func newCryptoReader(r io.Reader, strKey string, derivation int) (c *NaclPipe, err error) {
func newCryptoReader(r io.Reader, password string, derivation int) (io.Reader, error) {
	//salt := make([]byte, 16)
	c := new(NaclPipe)

	/* init values/vars */
	c.initialize(derivation)

	/* let's derive a key */
	err := c.initReader(r, password)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Read will read the amount of
func (c *NaclPipe) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.shazam()

	//b := make([]byte, len(p))
	b := make([]byte, len(p)+secretbox.Overhead)

	//n, err = c.rd.Read(b)
	n, err = io.ReadFull(c.rd, b)
	if err != nil && err != io.ErrUnexpectedEOF {
		return n, err
	}

	pt, res := secretbox.Open(nil, b[:n], c.cntNonce, c.dKey)
	if res == true {
		copy(p, pt)
		c.cnt++
		return len(pt), nil
	}
	return 0, ErrRead
}

//
//
// WRITER
//
//

func (c *NaclPipe) writeSalt() (err error) {
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

// NewWriter initialize an io.Writer using 'password' and the selected derivation function.
// Example:
//	cryptoWriter, err := naclpipe.NewWriter(os.Stdout, "mypassword", naclpipe.DerivateScrypt)
//	if err != nil {
//		return err
//	}
func NewWriter(w io.Writer, password string, derivation int) (io.Writer, error) {
	return newCryptoWriter(w, password, derivation)
}

//func newCryptoWriter(w io.Writer, strKey string, derivation int) (c *NaclPipe, err error) {
func newCryptoWriter(w io.Writer, password string, derivation int) (io.Writer, error) {
	//salt := make([]byte, 16)
	c := new(NaclPipe)

	/* init values/vars */
	c.initialize(derivation)

	/* let's derive a key */
	err := c.initWriter(w, password)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// SHA3 the counter use it as nonce
func (c *NaclPipe) Write(p []byte) (n int, err error) {
	c.shazam()

	if c.cnt == 0 {
		n, err = c.wr.Write(c.salt)
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
		fmt.Fprintf(os.Stderr, "we should write %d but wrote %d (err:%v)\n", len(ct), n, err)
	}

	n = len(p)
	return
}
