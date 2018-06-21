package naclpipe

import (
	"crypto/rand"
	"errors"
	"testing"
)

const (
	testSalt = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
)

var (
	errReader = errors.New("reader error")
)

type TestReaderZero struct {
}
type TestReaderFail struct {
}

func (r *TestReaderZero) Read(b []byte) (n int, err error) {
	lb := make([]byte, len(b))
	copy(b, lb)
	return len(b), nil
}

func (r *TestReaderFail) Read(b []byte) (n int, err error) {
	return 0, errReader
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
 * initReader TESTING
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
 * naclpipe.NewReader(r io.Reader, strKey string, derivation int) (io.Reader, error)
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

func TestNewReaderFailReader(t *testing.T) {
	tr := &TestReaderFail{}

	_, err := NewReader(tr, "password", DerivateScrypt)
	switch err {
	case errReader:
	default:
		t.Errorf("should warn it IS unsafe: %v", err)
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
