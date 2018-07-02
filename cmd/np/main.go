// +build go1.7

// Copyright 2016-2018 (c) Eric "eau" Augé <eau+naclpipe@unix4fun.net>

// naclpipe a simple (lame?) encryption pipe
// quickly made to understand interface / io.Reader / io.Writer
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
	Version                                 = "0.2.1"
	EnvAlg                                  = "NPALG"
	EnvKey                                  = "NPKEY"
)

var npLog *DebugLog

func init() {
	npLog = NewDebugLog(os.Stderr, "<naclpipe> ")
}

// banner is just a banner function.
func banner(cmd string) {
	fmt.Fprintf(os.Stderr, "(N)acl (P)ipe v%s¦ a simple encryption pipe\n", Version)
	fmt.Fprintf(os.Stderr, "using naclpipe %v library\n", naclpipe.Version)
}

// usage display the command line usage
func usage() {
	banner(os.Args[0])
	fmt.Printf("%s [options]\n", os.Args[0])
	fmt.Printf("--\n")
	fmt.Printf("[environment variables]\n")
	fmt.Printf("NPKEY: (same as -k)\n")
	fmt.Printf("NPALG: (same as -a)\n")
	fmt.Printf("--\n")
	flag.PrintDefaults()
}

func main() {
	// setup basic usage messages */
	flag.Usage = usage

	/* default is encrypt */
	/* decrypt if necessary */
	decFlag := flag.Bool("d", false, "decrypt")

	// algorithm, unknown == argon2id
	algFlag := flag.String("a", "argon", "old|scrypt|argon")

	// buffer size
	szFlag := flag.Int("s", defaultBufferSize, "buffer size")

	/* key to provide */
	keyFlag := flag.String("k", defaultInsecureHardcodedKeyForLazyFolks, "key value")

	//dbgFlag := flag.Bool("v", false, "verbose log")
	hlpFlag := flag.Bool("h", false, "help")

	//verbFlag := flag.Int("v", 0, "verbosity level")

	flag.Parse()

	if len(flag.Args()) != 0 || *hlpFlag == true {
		flag.Usage()
		os.Exit(1)
	}

	// password
	password := *keyFlag
	alg := *algFlag
	bufSize := *szFlag

	keyEnv := os.Getenv(EnvKey)
	keyDerivationAlgEnv := os.Getenv(EnvAlg)

	if len(keyEnv) > 0 {
		password = keyEnv
	}

	if len(keyDerivationAlgEnv) > 0 {
		alg = keyDerivationAlgEnv
	}

	// derivation..
	derivation := naclpipe.DerivateArgon2id
	switch alg {
	case "old":
		derivation = naclpipe.DerivateScrypt010
	case "scrypt":
		derivation = naclpipe.DerivateScrypt
	}

	/*
		fmt.Fprintf(os.Stderr, "DERIVATION: %d/%s\n", derivation, alg)
		fmt.Fprintf(os.Stderr, "KEY: %s\n", password)
	*/

	// set the log level default is 0
	//npLog.Set(*verbFlag)

	// we define env variables to supersede command line params
	// for repetitive operation

	buf := make([]byte, bufSize)
	switch *decFlag {
	case true:
		// Decrypt
		crd, err := naclpipe.NewReader(os.Stdin, password, derivation)
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
		cwr, err := naclpipe.NewWriter(os.Stdout, password, derivation)
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
