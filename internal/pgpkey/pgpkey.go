// Package pgpkey loads the recipient's OpenPGP public key, classifies its
// validity and encrypts messages to it. No secret key material is ever
// accepted or held.
package pgpkey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrExpired means the key is otherwise sound (fingerprint matches, not
// revoked) but the primary key or every encryption-capable key has expired.
// It is the only condition that leads to delivery-only mode.
var ErrExpired = errors.New("pgp key expired")

// Key is a validated recipient public key.
type Key struct {
	entity      *openpgp.Entity
	fingerprint string
	expired     atomic.Bool // sticky: only a restart clears it
}

// Load decodes the Base64 public key (binary or ASCII-armored inside) and
// verifies that the primary key fingerprint equals wantFingerprint
// (upper-case hex). It does not judge expiry or revocation; see Check.
func Load(b64, wantFingerprint string) (*Key, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return nil, errors.New("public key is not valid Base64")
	}
	var el openpgp.EntityList
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN")) {
		el, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(raw))
	} else {
		el, err = openpgp.ReadKeyRing(bytes.NewReader(raw))
	}
	if err != nil {
		return nil, fmt.Errorf("public key cannot be parsed: %w", err)
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("expected exactly one public key, found %d", len(el))
	}
	e := el[0]
	if e.PrivateKey != nil {
		return nil, errors.New("secret key material supplied; only the public key may be configured")
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil {
			return nil, errors.New("secret key material supplied; only the public key may be configured")
		}
	}
	fp := strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
	if fp != wantFingerprint {
		return nil, errors.New("primary key fingerprint does not match PGP_FINGERPRINT")
	}
	return &Key{entity: e, fingerprint: fp}, nil
}

// Fingerprint returns the primary key fingerprint in upper-case hex.
func (k *Key) Fingerprint() string { return k.fingerprint }

type candidate struct {
	pub *packet.PublicKey
	sig *packet.Signature
}

// encryptionCandidates lists every non-revoked key the library could pick
// for encryption, ignoring expiry: flagged subkeys, plus the primary key
// when it carries the encryption flag itself.
func (k *Key) encryptionCandidates(now time.Time, primarySig *packet.Signature) []candidate {
	var out []candidate
	for i := range k.entity.Subkeys {
		sk := &k.entity.Subkeys[i]
		if sk.Sig != nil && sk.Sig.FlagsValid && sk.Sig.FlagEncryptCommunications &&
			sk.PublicKey.PubKeyAlgo.CanEncrypt() && !sk.Revoked(now) {
			out = append(out, candidate{sk.PublicKey, sk.Sig})
		}
	}
	if primarySig.FlagsValid && primarySig.FlagEncryptCommunications &&
		k.entity.PrimaryKey.PubKeyAlgo.CanEncrypt() {
		out = append(out, candidate{k.entity.PrimaryKey, primarySig})
	}
	return out
}

// notAfter returns the last instant at which pub is usable under sig, or the
// zero time when it never expires.
func notAfter(pub *packet.PublicKey, sig *packet.Signature) time.Time {
	var t time.Time
	if sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs != 0 {
		t = pub.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
	}
	if sig.SigLifetimeSecs != nil && *sig.SigLifetimeSecs != 0 {
		s := sig.CreationTime.Add(time.Duration(*sig.SigLifetimeSecs) * time.Second)
		if t.IsZero() || s.Before(t) {
			t = s
		}
	}
	return t
}

func expiredAt(pub *packet.PublicKey, sig *packet.Signature, now time.Time) bool {
	t := notAfter(pub, sig)
	return !t.IsZero() && now.Unix() > t.Unix()
}

// Check classifies the key at time now.
//
//   - nil: usable for encryption.
//   - ErrExpired: expiry is the only problem.
//   - any other error: revoked, no encryption key, not yet valid, ...; the
//     service must not start.
func (k *Key) Check(now time.Time) error {
	e := k.entity
	sig, ident := e.PrimarySelfSignature()
	if sig == nil {
		return errors.New("public key has no usable self-signature")
	}
	if e.Revoked(now) {
		return errors.New("primary key is revoked")
	}
	if ident != nil && ident.Revoked(now) {
		return errors.New("every user ID of the key is revoked")
	}
	if e.PrimaryKey.CreationTime.Unix() > now.Unix() || sig.CreationTime.Unix() > now.Unix() {
		return errors.New("primary key is not yet valid (creation time is in the future)")
	}
	cands := k.encryptionCandidates(now, sig)
	if len(cands) == 0 {
		return errors.New("public key has no (non-revoked) encryption-capable key")
	}
	if expiredAt(e.PrimaryKey, sig, now) {
		k.expired.Store(true)
		return ErrExpired
	}
	usable, future := 0, 0
	for _, c := range cands {
		switch {
		case c.pub.CreationTime.Unix() > now.Unix() || c.sig.CreationTime.Unix() > now.Unix():
			future++
		case !expiredAt(c.pub, c.sig, now):
			usable++
		}
	}
	if usable == 0 {
		if future == len(cands) {
			return errors.New("no encryption key is valid yet (creation time is in the future)")
		}
		k.expired.Store(true)
		return ErrExpired
	}
	if k.expired.Load() {
		// Once expiry has been observed the service stays in delivery-only
		// mode until it is restarted, even if the clock steps backwards.
		return ErrExpired
	}
	if _, ok := e.EncryptionKey(now); !ok {
		return errors.New("OpenPGP library found no valid encryption key")
	}
	return nil
}

// Valid reports whether the key can currently be used for encryption.
func (k *Key) Valid(now time.Time) bool { return k.Check(now) == nil }

// Expiry returns the instant after which encryption stops being possible:
// the earlier of the primary key's expiry and the latest expiry among the
// encryption-capable keys. ok is false when the key never expires.
func (k *Key) Expiry(now time.Time) (t time.Time, ok bool) {
	sig, _ := k.entity.PrimarySelfSignature()
	if sig == nil {
		return time.Time{}, false
	}
	primary := notAfter(k.entity.PrimaryKey, sig)
	var latest time.Time
	never := false
	cands := k.encryptionCandidates(now, sig)
	for _, c := range cands {
		n := notAfter(c.pub, c.sig)
		if n.IsZero() {
			never = true
		} else if n.After(latest) {
			latest = n
		}
	}
	if never || len(cands) == 0 {
		latest = time.Time{}
	}
	switch {
	case primary.IsZero() && latest.IsZero():
		return time.Time{}, false
	case primary.IsZero():
		return latest, true
	case latest.IsZero() || primary.Before(latest):
		return primary, true
	default:
		return latest, true
	}
}

// Encrypt encrypts plaintext to the key as an ASCII-armored OpenPGP message.
// It re-checks validity at now first and never falls back to plaintext. The
// returned subkeyID is the 64-bit key ID (upper-case hex) of the key that
// was actually used.
func (k *Key) Encrypt(now time.Time, plaintext []byte) (armored []byte, subkeyID string, err error) {
	if err := k.Check(now); err != nil {
		return nil, "", err
	}
	encKey, ok := k.entity.EncryptionKey(now)
	if !ok {
		return nil, "", errors.New("no valid encryption key")
	}
	cfg := &packet.Config{
		Time:                   func() time.Time { return now },
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
	}
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, "", fmt.Errorf("armor: %w", err)
	}
	pw, err := openpgp.Encrypt(aw, []*openpgp.Entity{k.entity}, nil, &openpgp.FileHints{IsBinary: true}, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt: %w", err)
	}
	if _, err := pw.Write(plaintext); err != nil {
		return nil, "", fmt.Errorf("encrypt: %w", err)
	}
	// Closing finalises the encrypted data packet (MDC) and the armor
	// trailer; a message is only complete once both succeed.
	if err := pw.Close(); err != nil {
		return nil, "", fmt.Errorf("encrypt: finalise: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, "", fmt.Errorf("armor: finalise: %w", err)
	}
	return buf.Bytes(), fmt.Sprintf("%016X", encKey.PublicKey.KeyId), nil
}

// SelfTest performs a real in-memory encryption of a short test message and
// checks that a complete armored message came out. Nothing is stored or
// sent, and decryption is not (and cannot be) verified here.
func (k *Key) SelfTest(now time.Time) error {
	const probe = "pgp-mailer startup encryption self-test"
	out, _, err := k.Encrypt(now, []byte(probe))
	if err != nil {
		return err
	}
	if bytes.Contains(out, []byte(probe)) {
		return errors.New("self-test output contains the plaintext")
	}
	block, err := armor.Decode(bytes.NewReader(out))
	if err != nil {
		return fmt.Errorf("self-test output is not a valid armored message: %w", err)
	}
	if block.Type != "PGP MESSAGE" {
		return fmt.Errorf("self-test produced unexpected armor type %q", block.Type)
	}
	// The first packet must be a public-key encrypted session key.
	p, err := packet.NewReader(block.Body).Next()
	if err != nil {
		return fmt.Errorf("self-test output cannot be parsed: %w", err)
	}
	if _, ok := p.(*packet.EncryptedKey); !ok {
		return fmt.Errorf("self-test output starts with unexpected packet %T", p)
	}
	return nil
}
