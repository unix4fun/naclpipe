// +build go1.7
// naclpipe a simple (lame?) encryption pipe
// quickly made to understand interface / io.Reader / io.Writer
// Copyright (c) eau <eau+naclpipe@unix4fun.net>
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	// naclpipe package
	"github.com/unix4fun/naclpipe"
)

const (
	// default Key (insecure obviously..)
	defaultInsecureHardcodedKeyForLazyFolks = "n4clp1pebleh!"
	defaultBufferSize                       = 4194304 // 4M
	Version                                 = "0.1.0"
)

var npLog *DebugLog

func init() {
	npLog = NewDebugLog(os.Stderr, "<naclpipe> ")
}

// banner is just a banner function.
func banner(cmd string) {
	fmt.Fprintf(os.Stderr, "Nacl Pipe v%s¦ a simple encryption pipe\n", Version)
	fmt.Fprintf(os.Stderr, "using Salsa20/Poly1305 AEAD\n")
}

// usage display the command line usage
func usage() {
	banner(os.Args[0])
	fmt.Printf("%s [options]\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {

	// setup basic usage messages */
	flag.Usage = usage

	/* default is encrypt */
	/* decrypt if necessary */
	decFlag := flag.Bool("d", false, "decrypt")
	//dbgFlag := flag.Bool("v", false, "verbose log")
	hlpFlag := flag.Bool("h", false, "help")
	/* key to provide */
	keyFlag := flag.String("k", defaultInsecureHardcodedKeyForLazyFolks, "key value")
	//verbFlag := flag.Int("v", 0, "verbosity level")

	flag.Parse()

	if len(flag.Args()) != 0 || *hlpFlag == true {
		flag.Usage()
		os.Exit(1)
	}

	// set the log level default is 0
	//npLog.Set(*verbFlag)

	buf := make([]byte, defaultBufferSize)
	switch *decFlag {
	case true:
		// Decrypt
		crd, err := naclpipe.NewReader(os.Stdin, *keyFlag)
		if err != nil {
			panic(err)
		}

	DecryptLoop:
		for {
			n, err := crd.Read(buf)
			switch err {
			case io.EOF:
				break DecryptLoop
			case nil:
				break
			default:
				panic(err)
			} // end of Switch

			_, err = os.Stdout.Write(buf[:n])
			if err != nil {
				panic(err)
			}
		} // End of DecryptLoop

	default:
		// Encrypt
		cwr, err := naclpipe.NewWriter(os.Stdout, *keyFlag)
		if err != nil {
			panic(err)
		}

	CryptLoop:
		for {
			n, err := io.ReadFull(os.Stdin, buf)
			switch err {
			case io.ErrUnexpectedEOF:
				_, err = cwr.Write(buf[:n])
				if err != nil {
					panic(err)
				}
				fallthrough
			case io.EOF:
				break CryptLoop
			case nil:
				break
			default:
				panic(err)
			} // end of Switch

			// we need salt if it's the first block
			_, err = cwr.Write(buf[:n])
			if err != nil {
				panic(err)
			}
		} // End of CryptLoop
	} // End of switch()
}
