// +build go1.10

package naclpipe

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	mrnd "math/rand"
)

const (
	testSalt = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
)

var (
	errReader = errors.New("reader error")
	errWriter = errors.New("writer error")
)

type TestReaderZero struct {
}
type TestReaderFail struct {
}
type TestReaderFailIO struct {
}

func (r *TestReaderZero) Read(b []byte) (n int, err error) {
	lb := make([]byte, len(b))
	copy(b, lb)
	return len(b), nil
}

func (r *TestReaderFail) Read(b []byte) (n int, err error) {
	return 0, errReader
}

func (r *TestReaderFailIO) Read(b []byte) (n int, err error) {
	lb := make([]byte, len(b))
	copy(b, lb)
	return len(b), io.ErrUnexpectedEOF
}

type TestWriter struct {
}

func (w *TestWriter) Write(b []byte) (n int, err error) {
	//fmt.Printf("TestWriterLog buf: %d bytes\n", len(b))
	return 0, errWriter
}

/*
 *
 *
 *
 *
 * INITIALIZE TESTING
 *
 *
 *
 *
 */

func TestNaclpipeInitialize(t *testing.T) {
	c := new(NaclPipe)

	// argon derivation
	c.initialize(DerivateArgon2id)

	switch v := c.params.(type) {
	case Argon2Params:
		// all good
	default:
		t.Errorf("wrong expected DerivateArgon2id(%d) vs %T", DerivateArgon2id, v)
	}

	// scrypt new derivation
	c.initialize(DerivateScrypt)

	switch v := c.params.(type) {
	case ScryptParams:
		// all good
	default:
		t.Errorf("wrong expected Scrypt(%d) vs %T", DerivateScrypt, v)
	}

	// scrypt new derivation
	c.initialize(DerivateScrypt010)

	switch v := c.params.(type) {
	case ScryptParams:
		// all good
	default:
		t.Errorf("wrong expected Scrypt010(%d) vs %T", DerivateScrypt010, v)
	}

}

/*
 *
 *
 *
 *
 * deriveKey TESTING
 *
 *
 *
 *
 */

func TestNaclDeriveKeyZeroSalt(t *testing.T) {
	salt := make([]byte, 32)

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.deriveKey(salt, "password")
	switch err {
	case ErrUnsafe:
	default: // different error is weird
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestNaclDeriveKeyShortSalt(t *testing.T) {
	salt := make([]byte, 0)

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.deriveKey(salt, "password")
	switch err {
	case ErrUnsafe:
	default: // different error is weird
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestNaclDeriveKeyShortKey(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)

	//fmt.Printf("testtest: %d\n", len(salt))

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err = c.deriveKey(salt, "pass")
	switch err {
	case ErrUnsafe:
	default: // different error is weird
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestNaclpipeDeriveKeyUnsupported(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)

	//fmt.Printf("testtest: %d\n", len(salt))

	c := new(NaclPipe)

	err = c.deriveKey(salt, "password")
	switch err {
	case ErrUnsupported:
	default: // different error is weird
		t.Errorf("should warn it IS unsupported: %v", err)
	}
}

func TestNaclDeriveKeyOK(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)

	//fmt.Printf("testtest: %d\n", len(salt))

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err = c.deriveKey(salt, "password")
	switch err {
	case nil:
	default: // different error is weird
		t.Errorf("should say it IS OK: %v", err)
	}
}

/*
 *
 *
 *
 *
 * initReader/initWriter TESTING
 *
 *
 *
 *
 */

func TestInitReaderZeroSalt(t *testing.T) {
	tr := &TestReaderZero{}

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.initReader(tr, "password")
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestInitReaderShortPass(t *testing.T) {
	//tr := &TestReaderZero{}

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.initReader(rand.Reader, "pass")
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestInitWriterShortPass(t *testing.T) {
	tr := &TestWriter{}

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.initWriter(tr, "pass")
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}
}

func TestInitReaderFail(t *testing.T) {
	tr := &TestReaderFail{}

	c := new(NaclPipe)
	c.initialize(DerivateArgon2id)

	err := c.initReader(tr, "password")
	switch err {
	case errReader:
	default:
		t.Errorf("should display reader fail: %v", err)
	}
}

/*
 *
 *
 *
 *
 * PUBLIC INTERFACE TESTING
 * naclpipe.NewReader(r io.Reader, password string, derivation int) (io.Reader, error)
 * naclpipe.NewWriter(r io.Writer, password string, derivation int) (io.Writer, error)
 *
 *
 *
 *
 */

func TestNewReaderZeroSalt(t *testing.T) {
	tr := &TestReaderZero{}

	_, err := NewReader(tr, "password", DerivateScrypt)
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}

}

func TestNewReaderShortPass(t *testing.T) {
	_, err := NewReader(rand.Reader, "pass", DerivateScrypt)
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}

}

func TestNewWriterShortPass(t *testing.T) {
	tw := &TestWriter{}

	_, err := NewWriter(tw, "pass", DerivateScrypt)
	switch err {
	case ErrUnsafe:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}

}

func TestNewReaderFailReader(t *testing.T) {
	tr := &TestReaderFail{}

	_, err := NewReader(tr, "password", DerivateScrypt)
	switch err {
	case errReader:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
	}

}

func TestNewWriterFailWriter(t *testing.T) {
	tw := &TestWriter{}
	cw, err := NewWriter(tw, "password", DerivateScrypt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := []byte("testtesttest")
	n, err := cw.Write(buf)
	if err != errWriter {
		t.Fatalf("unexpected error: %d/%v", n, err)
	}

}

func TestNewReaderDefaultDerivation(t *testing.T) {
	cr, err := NewReader(rand.Reader, "password", 233)
	switch err {
	case nil:
		c, ok := cr.(*NaclPipe)
		if ok {
			switch v := c.params.(type) {
			case Argon2Params:
				// all good
			default:
				t.Errorf("wrong expected DerivateArgon2id(%d) vs %T", DerivateArgon2id, v)
			}
		} else {
			t.Errorf("wrong naclpipe structure %T", cr)
		}
	default:
		t.Errorf("no error but: %v", err)
	}

}

func TestNewReaderValidDerivationScrypt(t *testing.T) {
	cr, err := NewReader(rand.Reader, "password", DerivateScrypt)
	switch err {
	case nil:
		c, ok := cr.(*NaclPipe)
		if ok {
			switch v := c.params.(type) {
			case ScryptParams:
				// all good
			default:
				t.Errorf("wrong expected DerivateScrypt(%d) vs %T", DerivateScrypt, v)
			}
		} else {
			t.Errorf("wrong naclpipe structure %T", cr)
		}
	default:
		t.Errorf("no error but: %v", err)
	}

}

func TestNewReaderValidDerivationArgon(t *testing.T) {
	cr, err := NewReader(rand.Reader, "password", DerivateArgon2id)
	switch err {
	case nil:
		c, ok := cr.(*NaclPipe)
		if ok {
			switch v := c.params.(type) {
			case Argon2Params:
				// all good
			default:
				t.Errorf("wrong expected DerivateArgon2id(%d) vs %T", DerivateArgon2id, v)
			}
		} else {
			t.Errorf("wrong naclpipe structure %T", cr)
		}
	default:
		t.Errorf("no error but: %v", err)
	}

}

func TestNewReaderValidDerivationScrypt010(t *testing.T) {
	cr, err := NewReader(rand.Reader, "password", DerivateScrypt010)
	switch err {
	case nil:
		c, ok := cr.(*NaclPipe)
		if ok {
			switch v := c.params.(type) {
			case ScryptParams:
				// all good
				if v.CostParam != oldScryptCostParam {
					t.Errorf("wrong expected DerivateScrypt010 params(%d) vs %T", oldScryptCostParam, v.CostParam)
				}
			default:
				t.Errorf("wrong expected DerivateScrypt(%d) vs %T", DerivateScrypt010, v)
			}
		} else {
			t.Errorf("wrong naclpipe structure %T", cr)
		}
	default:
		t.Errorf("no error but: %v", err)
	}

}

/*
 *
 *
 *
 *
 * PUBLIC INTERFACE TESTING
 * naclpipe.Read(p []byte) (n int , err error)
 *
 *
 *
 *
 */

func TestReadZeroLength(t *testing.T) {
	b := make([]byte, 0)

	cr, err := NewReader(rand.Reader, "password", DerivateArgon2id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	n, err := cr.Read(b)
	if err != nil {
		t.Fatalf("unexpected error: %v (vs nil)", err)
	}

	if n != 0 {
		t.Fatalf("unexpected read %d bytes (vs 0)", n)
	}
}

func TestReadInvalidReaderByte(t *testing.T) {
	b := make([]byte, 1)

	cr, err := NewReader(rand.Reader, "password", DerivateArgon2id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	n, err := cr.Read(b)
	if err != ErrRead {
		t.Errorf("unexpected error: %v (vs nil)", err)
	}

	if n != 0 {
		t.Errorf("unexpected read %d bytes (vs 0)", n)
	}
}

func TestReadUnexpectedEndIo(t *testing.T) {
	tr := &TestReaderFailIO{}
	//b := make([]byte, 32)

	cr, err := NewReader(tr, "password", DerivateArgon2id)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("unexpected error: %v", err)
	}

	if cr != nil {
		t.Errorf("unexpected reader: %T/%p/%v", cr, cr, cr)
	}
}

func TestReadWrite(t *testing.T) {
	mr := mrnd.Intn(100)
	mrk := mrnd.Intn(1024)
	size := mr * mrk * 1024
	b := make([]byte, size)
	c := make([]byte, size)
	iobuf := new(bytes.Buffer)

	for i := 0; i < 10; i++ {
		t.Logf("[%d] size: %d x %d MB block", i, mr, mrk)

		// READ RANDOM DATA
		n, err := rand.Read(b)
		if err != nil {
			t.Fatalf("reading rand (%d) error: %v", err, n)
		}

		// let's do the SHA
		origSha := sha256.Sum256(b)

		cw, err := NewWriter(iobuf, "password", DerivateArgon2id)
		if err != nil {
			t.Fatalf("writer error: %v", err)
		}

		// CRYPT IT
		n, err = cw.Write(b)
		if err != nil {
			t.Fatalf("crypto writer (%d bytes) error: %v", n, err)
		}

		// CREATE CRYPTO READER
		cr, err := NewReader(iobuf, "password", DerivateArgon2id)
		if err != nil {
			t.Fatalf("reader setup fail")
		}

		// READ CRYPTED DATA
		n, err = cr.Read(c)
		if err != nil || n == 0 {
			t.Fatalf("unexpected error: %v (vs nil) n: %d", err, n)
		}

		// the sha after decryption
		rwSha := sha256.Sum256(c)

		if bytes.Equal(origSha[:], rwSha[:]) != true {
			t.Fatalf("sha do not match")
		}

		iobuf.Reset()
		mr = mrnd.Intn(100)
		mrk = mrnd.Intn(1024)
	}

}
