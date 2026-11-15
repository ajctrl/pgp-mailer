package pgpkey

import (
	"errors"
	"strings"
	"testing"
	"time"

	"pgp-mailer/internal/pgptest"
)

var (
	t0   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day  = 24 * time.Hour
	year = uint32(365 * 24 * 3600)
)

func load(t *testing.T, k *pgptest.Key) *Key {
	t.Helper()
	key, err := Load(k.PublicBase64(), k.Fingerprint())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return key
}

func TestValidKeyEncryptsAndDecrypts(t *testing.T) {
	tk := pgptest.New(t0, 0)
	for name, b64 := range map[string]string{"binary": tk.PublicBase64(), "armored": tk.PublicArmoredBase64()} {
		key, err := Load(b64, tk.Fingerprint())
		if err != nil {
			t.Fatalf("%s: Load: %v", name, err)
		}
		now := t0.Add(day)
		if err := key.Check(now); err != nil {
			t.Fatalf("%s: Check: %v", name, err)
		}
		if err := key.SelfTest(now); err != nil {
			t.Fatalf("%s: SelfTest: %v", name, err)
		}
		if _, ok := key.Expiry(now); ok {
			t.Errorf("%s: key without lifetime reports an expiry", name)
		}
		armored, subkeyID, err := key.Encrypt(now, []byte("secret 本文"))
		if err != nil {
			t.Fatalf("%s: Encrypt: %v", name, err)
		}
		if strings.Contains(string(armored), "secret") {
			t.Fatalf("%s: ciphertext contains plaintext", name)
		}
		if want := strings.ToUpper(tk.Entity.Subkeys[0].PublicKey.KeyIdString()); subkeyID != want {
			t.Errorf("%s: subkey id = %s, want %s", name, subkeyID, want)
		}
		got, err := tk.Decrypt(armored, now)
		if err != nil {
			t.Fatalf("%s: Decrypt: %v", name, err)
		}
		if string(got) != "secret 本文" {
			t.Errorf("%s: decrypted %q", name, got)
		}
	}
}

func TestLoadRejections(t *testing.T) {
	tk := pgptest.New(t0, 0)
	other := pgptest.New(t0, 0)
	cases := map[string]struct{ b64, fp string }{
		"not base64":           {"!!!", tk.Fingerprint()},
		"not a key":            {"aGVsbG8gd29ybGQ=", tk.Fingerprint()},
		"fingerprint mismatch": {tk.PublicBase64(), other.Fingerprint()},
		"secret key supplied":  {tk.SecretBase64(), tk.Fingerprint()},
	}
	for name, c := range cases {
		if _, err := Load(c.b64, c.fp); err == nil {
			t.Errorf("%s: Load succeeded", name)
		} else if errors.Is(err, ErrExpired) {
			t.Errorf("%s: classified as expiry", name)
		}
	}
}

func TestExpiryIsTheOnlyDeliveryOnlyCondition(t *testing.T) {
	now := t0.Add(400 * day)

	t.Run("primary expired", func(t *testing.T) {
		key := load(t, pgptest.New(t0, year))
		if err := key.Check(now); !errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want ErrExpired", err)
		}
		if _, _, err := key.Encrypt(now, []byte("x")); !errors.Is(err, ErrExpired) {
			t.Fatalf("Encrypt = %v, want ErrExpired", err)
		}
		exp, ok := key.Expiry(now)
		if !ok || !exp.Equal(t0.Add(365*day)) {
			t.Errorf("Expiry = %v %v", exp, ok)
		}
	})

	t.Run("only the encryption subkey expired", func(t *testing.T) {
		tk := pgptest.New(t0, 0)
		tk.SetSubkeyLifetime(t0, year)
		key := load(t, tk)
		if err := key.Check(t0.Add(day)); err != nil {
			t.Fatalf("Check before expiry: %v", err)
		}
		// A fresh instance: Check above did not latch anything, but keep
		// the two assertions independent.
		key = load(t, tk)
		if err := key.Check(now); !errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want ErrExpired", err)
		}
		if exp, ok := key.Expiry(now); !ok || !exp.Equal(t0.Add(365*day)) {
			t.Errorf("Expiry = %v %v", exp, ok)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		tk := pgptest.New(t0, 0)
		tk.Revoke(t0.Add(day))
		err := load(t, tk).Check(now)
		if err == nil || errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want a fatal error", err)
		}
	})

	t.Run("revoked and expired is still fatal", func(t *testing.T) {
		tk := pgptest.New(t0, year)
		tk.Revoke(t0.Add(day))
		err := load(t, tk).Check(now)
		if err == nil || errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want a fatal error", err)
		}
	})

	t.Run("encryption subkey revoked", func(t *testing.T) {
		tk := pgptest.New(t0, 0)
		tk.RevokeSubkey(t0.Add(day))
		err := load(t, tk).Check(now)
		if err == nil || errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want a fatal error", err)
		}
	})

	t.Run("no encryption subkey", func(t *testing.T) {
		tk := pgptest.New(t0, 0)
		tk.Entity.Subkeys = nil
		err := load(t, tk).Check(now)
		if err == nil || errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want a fatal error", err)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		err := load(t, pgptest.New(t0, 0)).Check(t0.Add(-day))
		if err == nil || errors.Is(err, ErrExpired) {
			t.Fatalf("Check = %v, want a fatal error", err)
		}
	})
}

func TestExpiryWhileRunningIsSticky(t *testing.T) {
	key := load(t, pgptest.New(t0, year))
	before, after := t0.Add(364*day), t0.Add(366*day)
	if !key.Valid(before) {
		t.Fatal("key should be valid before expiry")
	}
	if key.Valid(after) {
		t.Fatal("key should be invalid after expiry")
	}
	if key.Valid(before) {
		t.Fatal("expiry must stay latched until restart, even if the clock goes back")
	}
	if _, _, err := key.Encrypt(before, []byte("x")); !errors.Is(err, ErrExpired) {
		t.Fatalf("Encrypt after latch = %v, want ErrExpired", err)
	}
}
