# NP
(n)aCL (p)ipe

## ChangeLog
* 2018-06-24
  * bumped version 0.2.0
  * added argon2id & updated scrypt parameters
  * added environment variable for repetitive pipe using similar complex passphrase.
  * updated to introduce backward compatibility with old scrypt parameters (backward compatibility)
* 2018-04-02
  * renamed, updated, now using the [naclpipe](https://github.com/unix4fun/naclpipe) Go package io.Reader/io.Writer interface
  * First version 0.1.0

## Command Install

    go get -u github.com/unix4fun/naclpipe/cmd/np

## Command Usage

    $ echo "proutproutprout" | np -k=tagadaa  | np -d -k=tagadaa

## Requirements / Featuring (because there is always a star in your production..)

* [NaCL ECC 25519] (http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/golang.org/x/crypto/nacl) AEAD using Salsa20 w/ Poly1305 MAC
* [Scrypt] (http://en.wikipedia.org/wiki/Scrypt) for key stretching
* [Argon2] (https://en.wikipedia.org/wiki/Argon2) for today key stretching
* [SHA-3] (http://en.wikipedia.org/wiki/SHA-3) 256 for NONCE generation
* [Go] (http://golang.org) because it works.


