// Package pgptest generates throw-away OpenPGP keys for tests. The secret
// keys exist only inside the test process, to verify that what the service
// produced can actually be decrypted.
package pgptest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type Key struct {
	Entity *openpgp.Entity
}

func cfg(at time.Time, lifetimeSecs uint32) *packet.Config {
	return &packet.Config{
		Time:            func() time.Time { return at },
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		KeyLifetimeSecs: lifetimeSecs,
	}
}

// New creates a key (primary + encryption subkey) dated created. A non-zero
// lifetime applies to both the primary key and the subkey.
func New(created time.Time, lifetimeSecs uint32) *Key {
	e, err := openpgp.NewEntity("pgp-mailer test", "", "ops@example.com", cfg(created, lifetimeSecs))
	if err != nil {
		panic(err)
	}
	return &Key{Entity: e}
}

// SetSubkeyLifetime re-signs the binding of the encryption subkey with the
// given lifetime, leaving the primary key untouched.
func (k *Key) SetSubkeyLifetime(at time.Time, lifetimeSecs uint32) {
	sk := &k.Entity.Subkeys[0]
	sk.Sig.KeyLifetimeSecs = &lifetimeSecs
	sk.Sig.CreationTime = at
	if err := sk.Sig.SignKey(sk.PublicKey, k.Entity.PrivateKey, cfg(at, 0)); err != nil {
		panic(err)
	}
}

// Revoke adds a primary key revocation.
func (k *Key) Revoke(at time.Time) {
	if err := k.Entity.RevokeKey(packet.KeyCompromised, "test", cfg(at, 0)); err != nil {
		panic(err)
	}
}

// RevokeSubkey revokes the encryption subkey.
func (k *Key) RevokeSubkey(at time.Time) {
	if err := k.Entity.RevokeSubkey(&k.Entity.Subkeys[0], packet.KeyRetired, "test", cfg(at, 0)); err != nil {
		panic(err)
	}
}

// Fingerprint returns the primary fingerprint in upper-case hex.
func (k *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(k.Entity.PrimaryKey.Fingerprint))
}

// PublicBinary returns the serialized public key.
func (k *Key) PublicBinary() []byte {
	var buf bytes.Buffer
	if err := k.Entity.Serialize(&buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// PublicBase64 returns the Base64 of the binary public key.
func (k *Key) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(k.PublicBinary())
}

// PublicArmoredBase64 returns the Base64 of the ASCII-armored public key.
func (k *Key) PublicArmoredBase64() string {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		panic(err)
	}
	w.Write(k.PublicBinary())
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// SecretBase64 returns the Base64 of the serialized secret key.
func (k *Key) SecretBase64() string {
	var buf bytes.Buffer
	if err := k.Entity.SerializePrivate(&buf, nil); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Decrypt decrypts an armored message with the secret key, as of at.
func (k *Key) Decrypt(armored []byte, at time.Time) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(armored))
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{k.Entity}, nil, cfg(at, 0))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(md.UnverifiedBody)
}
