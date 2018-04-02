# NP
(N)aCL (P)ipe

## ChangeLog
* 2018-04-02
  * renamed, updated, now using the [naclpipe](https://github.com/unix4fun/naclpipe) Go package io.Reader/io.Writer interface
  * First version 0.1.0

## Command Install
    go get github.com/unix4fun/naclpipe/cmd/np

## Featuring (because there is always a star in your production..)

* [NaCL ECC 25519] (http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/golang.org/x/crypto/nacl) with AEAD
(using Salsa20 w/ Poly1305 MAC)
* [Scrypt] (http://en.wikipedia.org/wiki/Scrypt) for key stretching
* [SHA-3] (http://en.wikipedia.org/wiki/SHA-3) for NONCE generation
* [Go] (http://golang.org) because I like trying something new and promising.


## Command Usage

    $ echo "proutproutprout" | ./np -k=tagadaa  | ./np -d -k=tagadaa
