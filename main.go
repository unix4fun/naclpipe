// +build go1.4
// naclpipe a simple (lame?) encryption pipe
// quickly made to understand interface / io.Reader / io.Writer
// eau <eau-code@unix4fun.net>
package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
)

const (
	defaultBufferSize = 32768
)

var npLog *DebugLog

func init() {
	npLog = NewDebugLog(os.Stderr, "<naclpipe> ")
}

// banner is just a banner function.
func banner(cmd string) {
	fmt.Printf("Nacl Go Pipe v%s¦ A simple (lame?) encryption pipe\n", npVersion)
	fmt.Printf("using Salsa20/Poly1305 AEAD") //or AES256-GCM coming soon
}

// usage display the command line usage
func usage() {
	npLog.Printf(1, "CALL usage()\n")
	banner(os.Args[0])
	fmt.Printf("%s [options]\n", os.Args[0])
	flag.PrintDefaults()
	npLog.Printf(1, "RET usage()\n")
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
	keyFlag := flag.String("k", "n4clp1pebleh!", "key value")
	verbFlag := flag.Int("v", 0, "verbosity level")

	flag.Parse()

	if len(flag.Args()) != 0 || *hlpFlag == true {
		flag.Usage()
		os.Exit(1)
	}

	// set the log level default is 0
	npLog.Set(*verbFlag)

	// TODO XXX we need to display the selected blocksize at encryption and
	// propose it as an argument in case different host have different stdin
	// blocksize
	stdinFileStruct, _ := os.Stdin.Stat()
	bufSize := stdinFileStruct.Size()
	npLog.Printf(2, "bufSize: %d\n", bufSize)
	if bufSize < (secretbox.Overhead * 2) {
		bufSize = defaultBufferSize
	}

	switch *decFlag {
	case true:
		// Decrypt
		crd, err := NewCryptoReader(os.Stdin, *keyFlag)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, bufSize)
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
		cwr, err := NewCryptoWriter(os.Stdout, *keyFlag)
		if err != nil {
			panic(err)
		}

		buf := make([]byte, bufSize-secretbox.Overhead)
	CryptLoop:
		for {
			//n, err := os.Stdin.Read(buf)
			n, err := io.ReadFull(os.Stdin, buf)
			//fmt.Printf("READ: %d / %v\n", n, err)
			switch err {
			case io.EOF:
				break CryptLoop
			case io.ErrUnexpectedEOF:
				break
			case nil:
				break
			default:
				panic(err)
			} // end of Switch

			_, err = cwr.Write(buf[:n])
			if err != nil {
				panic(err)
			}
		} // End of CryptLoop
	} // End of switch()
}
