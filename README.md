# naclpipe
NaCL Pipe Go Package

## Purpose
A simple experimental Go package providing an io.Reader/io.Writer interface with an NaCL (pronounced 'Salt') crypto backend.

  * [np](https://www.github.com/unix4fun/naclpipe/tree/master/cmd/np)* is the previously called naclpipe tool using this Go package.


## ChangeLog
* 2018-11-17
  * remove old unsafe backware compatibility code.
  * tagged 0.2.0
* 2018-06-24
  * added argon2id key derivation function.
  * upgraded the key derivation function and the parameters to a 2018 flavor.
  * added some godoc documentation

* 2018-04-01
  * separating command 'np' and package 'naclpipe', this way package can eventually be reused as "crypto" stream.
  * reusable io.Reader/Writer interface.
  * Starting 'semver' and documenting, first version will be 0.1.0
            
* 2018-03-24
  * fixing the empty scrypt salt reported by Tom Eklof 
  * better handling of pipe input.
  * the structure has changed as the CSPRNG'ed salt is prefixed to the series of blocks

## Package Example Usage 

    import "github.com/unix4fun/naclpipe"

    // block size can be arbitrary, we read in block of datas
    block := make([]byte, 8192)

    // initilize my reader from stdin
    cryptoReader, err := naclpipe.NewReader(os.Stdin, "mysuperduperpassword", naclpipe.DerivateArgon2id)
    if err != nil {
        log.Fatalf("naclpipe error")
    }

    // read & decipher in block
    _, err := cryptoReader.Read(b)

## Package Usage Example / Tool

see *[np](https://www.github.com/unix4fun/naclpipe/tree/master/cmd/np)*.

## Package Doc

  * [godoc](https://godoc.org/github.com/unix4fun/naclpipe)

## Featuring (because there is always a star in your production..)

* [NaCL ECC 25519](http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/golang.org/x/crypto/nacl) AEAD using Salsa20 w/ Poly1305 MAC
* [Argon2](https://en.wikipedia.org/wiki/Argon2) for today key stretching.
* [Scrypt](http://en.wikipedia.org/wiki/Scrypt) for key stretching.
* [SHA-3](http://en.wikipedia.org/wiki/SHA-3) for NONCE generation.
* [Go](http://golang.org) because it works.
