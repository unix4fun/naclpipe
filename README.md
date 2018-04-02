# naclpipe
NaCL Pipe Go Package

## Purpose
A simple Go package providing an io.Reader/io.Writer interface with an NaCL (pronounced 'Salt') crypto backend.

*[np](https://www.github.com/unix4fun/naclpipe)* is the previously called naclpipe tool using this Go package.


## ChangeLog
* 2018-04-01
  * separating command 'np' and package 'naclpipe', this way package can eventually be reused as "crypto" stream.
  * reusable io.Reader/Writer interface.
  * Starting 'semver' and documenting, first version will be 0.1.0
            
* 2018-03-24
  * fixing the empty scrypt salt reported by Tom Eklof 
  * better handling of pipe input.
  * the structure has changed as the CSPRNG'ed salt is prefixed to the series of blocks

## Package Usage 

    import github.com/unix4fun/naclpipe

## Package Usage Example
Please see *[np](https://www.github.com/unix4fun/naclpipe/cmd/np)*.

## Package Doc
TODO

## Featuring (because there is always a star in your production..)

* [NaCL ECC 25519] (http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/golang.org/x/crypto/nacl) with AEAD
(using Salsa20 w/ Poly1305 MAC)
* [Scrypt] (http://en.wikipedia.org/wiki/Scrypt) for key stretching
* [SHA-3] (http://en.wikipedia.org/wiki/SHA-3) for NONCE generation
* [Go] (http://golang.org) because I like trying something new and promising.
