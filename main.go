// +build go1.4
// naclpipe a simple (lame?) encryption pipe
// quickly made to understand interface / io.Reader / io.Writer
// eau <eau-code@unix4fun.net>
package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
)

type cryptoPipe struct {
	dKey     *[32]byte // derived key
	cntNonce *[24]byte
	cnt      uint64 // nonce counter
	wr       io.Writer
	rd       io.Reader
}

func (c *cryptoPipe) init() {
	c.cntNonce = new([24]byte)
	c.dKey = new([32]byte)
	c.cnt = 0
}

// do SHA3 on the counter and update the cndNonce value...
// stream operate in blocks, then each blocks will be encrypted with its nonce.
func (c *cryptoPipe) shazam() (err error) {
	sha3hash := sha3.New256()
	countstr := fmt.Sprintf("%d", c.cnt)
	_, err = sha3hash.Write([]byte(countstr))
	if err != nil {
		return err
	}
	out := sha3hash.Sum(nil)
	copy(c.cntNonce[:], out[:24])
	return nil
}

func (c *cryptoPipe) Read(p []byte) (n int, err error) {
	err = c.shazam()
	if err != nil {
		panic(err)
	}

	b := make([]byte, len(p)+secretbox.Overhead)
	n, err = c.rd.Read(b)
	if err != nil {
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

// SHA3 the counter use it as nonce
func (c *cryptoPipe) Write(p []byte) (n int, err error) {
	err = c.shazam()
	if err != nil {
		panic(err)
	}

	ct := secretbox.Seal(nil, p, c.cntNonce, c.dKey)
	//fmt.Fprintf(os.Stderr, "bleh READ cryptopipe[%d] seal %d bytes\n", c.cnt, len(p))
	c.cnt++
	return c.wr.Write(ct)
}

func NewCryptoWriter(w io.Writer, strKey string) (c *cryptoPipe, err error) {
	salt := make([]byte, 16)
	c = new(cryptoPipe)

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

func NewCryptoReader(r io.Reader, strKey string) (c *cryptoPipe, err error) {
	salt := make([]byte, 16)
	c = new(cryptoPipe)

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

func banner(cmd string) {
	fmt.Printf("Nacl Go Pipe ¦ A simple (lame?) encryption pipe\n")
	fmt.Printf("using Salsa20/Poly1305 AEAD") //or AES256-GCM coming soon
}

func main() {

	/* default is encrypt */
	/* decrypt if necessary */
	decFlag := flag.Bool("d", false, "decrypt")
	//dbgFlag := flag.Bool("v", false, "verbose log")
	hlpFlag := flag.Bool("h", false, "help")
	/* key to provide */
	keyFlag := flag.String("k", "n4clp1pebleh!", "key value")

	flag.Parse()

	if len(flag.Args()) != 0 || *hlpFlag == true {
		banner(os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch *decFlag {
	case true:
		// Decrypt
		crd, err := NewCryptoReader(os.Stdin, *keyFlag)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 32768)
	DecryptLoop:
		for {
			n, err := crd.Read(buf)
			switch err {
			case io.EOF:
				//fmt.Fprintf(os.Stderr, "err: %v io.EOF: %v\n", err, io.EOF)
				break DecryptLoop
			case nil:
				//fmt.Fprintf(os.Stderr, "err: %v nil!!!\n", err)
			default:
				//fmt.Fprintf(os.Stderr, "err: %v\n", err)
				panic(err)
			}
			_, err = os.Stdout.Write(buf[:n])
			if err != nil {
				panic(err)
			}
		}

		//_, err = io.Copy(os.Stdout, crd)
		/* TODO: proper error mgmt
		if err != nil {
			panic(err)
		}
		*/
	default:
		// Encrypt
		cwr, err := NewCryptoWriter(os.Stdout, *keyFlag)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 32768)
	CryptLoop:
		for {
			n, err := os.Stdin.Read(buf)
			switch err {
			case io.EOF:
				//fmt.Fprintf(os.Stderr, "err: %v io.EOF: %v\n", err, io.EOF)
				//_, err = cwr.Write(buf)
				break CryptLoop
			case nil:
				//fmt.Fprintf(os.Stderr, "err: %v nil!!!\n", err)
			default:
				//fmt.Fprintf(os.Stderr, "err: %v\n", err)
				panic(err)
			} // end of Switch CryptoLoop

			_, err = cwr.Write(buf[:n])
			if err != nil {
				panic(err)
			}
		}

		/*
			n, err := io.Copy(cwr, os.Stdin)
			fmt.Printf("read: %d bytes\n", n)
			if err != nil {
				panic(err)
			}
		*/
	}
}
