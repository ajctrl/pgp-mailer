// Package mailmsg builds PGP/MIME (RFC 3156) messages with protected
// headers. Only the configured outer subject, addresses, Date and Message-ID
// are left in the clear.
package mailmsg

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// OuterSubject is the default unprotected subject.
const OuterSubject = "[pgp-mailer] encrypted notification"

// EncryptFunc encrypts plaintext into an ASCII-armored OpenPGP message and
// reports the ID of the encryption key used.
type EncryptFunc func(now time.Time, plaintext []byte) (armored []byte, subkeyID string, err error)

type Builder struct {
	From    *mail.Address
	To      *mail.Address
	Encrypt EncryptFunc
}

// Input is one validated notification.
type Input struct {
	ID            string // acceptance ID; becomes the local part of the Message-ID
	Source        string
	PublicSubject string // route configuration, visible before decryption
	Title         string
	Message       string
	Level         string
	Now           time.Time // acceptance time; fixes Date for all later resends
}

// Built is a complete RFC 5322 message ready for SMTP DATA.
type Built struct {
	Raw       []byte
	MessageID string
	SubkeyID  string
}

func (b *Builder) Build(in Input) (*Built, error) {
	date := in.Now.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
	// The domain follows the last "@": a quoted local part may contain one.
	domain := b.From.Address[strings.LastIndex(b.From.Address, "@")+1:]
	messageID := "<" + in.ID + "@" + domain + ">"
	from, to := b.From.String(), b.To.String()

	innerBoundary, err := boundary()
	if err != nil {
		return nil, err
	}
	var inner bytes.Buffer
	fmt.Fprintf(&inner, "Content-Type: multipart/mixed; boundary=\"%s\";\r\n protected-headers=\"v1\"\r\n", innerBoundary)
	fmt.Fprintf(&inner, "Subject: %s\r\n", encodeHeader("["+in.Level+"] "+in.Title, len("Subject: ")))
	fmt.Fprintf(&inner, "From: %s\r\n", from)
	fmt.Fprintf(&inner, "To: %s\r\n", to)
	fmt.Fprintf(&inner, "Date: %s\r\n", date)
	fmt.Fprintf(&inner, "Message-ID: %s\r\n", messageID)
	inner.WriteString("\r\n")
	fmt.Fprintf(&inner, "--%s\r\n", innerBoundary)
	inner.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	inner.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	body := strings.TrimRight(normalizeNewlines(in.Message), "\r\n") + "\r\n\r\n-- \r\n" +
		"pgp-mailer id=" + in.ID + " source=" + in.Source + " level=" + in.Level + "\r\n"
	writeBase64(&inner, []byte(body))
	fmt.Fprintf(&inner, "--%s--\r\n", innerBoundary)

	armored, subkeyID, err := b.Encrypt(in.Now, inner.Bytes())
	if err != nil {
		return nil, err
	}

	outerBoundary, err := boundary()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "From: %s\r\n", from)
	fmt.Fprintf(&out, "To: %s\r\n", to)
	publicSubject := in.PublicSubject
	if publicSubject == "" {
		publicSubject = OuterSubject
	}
	fmt.Fprintf(&out, "Subject: %s\r\n", encodeHeader(publicSubject, len("Subject: ")))
	fmt.Fprintf(&out, "Date: %s\r\n", date)
	fmt.Fprintf(&out, "Message-ID: %s\r\n", messageID)
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Auto-Submitted: auto-generated\r\n")
	fmt.Fprintf(&out, "Content-Type: multipart/encrypted;\r\n protocol=\"application/pgp-encrypted\";\r\n boundary=\"%s\"\r\n", outerBoundary)
	out.WriteString("\r\n")
	out.WriteString("This is an OpenPGP/MIME encrypted message (RFC 3156).\r\n")
	fmt.Fprintf(&out, "--%s\r\n", outerBoundary)
	out.WriteString("Content-Type: application/pgp-encrypted\r\n")
	out.WriteString("Content-Description: PGP/MIME version identification\r\n\r\n")
	out.WriteString("Version: 1\r\n\r\n")
	fmt.Fprintf(&out, "--%s\r\n", outerBoundary)
	out.WriteString("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
	out.WriteString("Content-Description: OpenPGP encrypted message\r\n")
	out.WriteString("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
	out.WriteString(strings.TrimRight(normalizeNewlines(string(armored)), "\r\n"))
	out.WriteString("\r\n\r\n")
	fmt.Fprintf(&out, "--%s--\r\n", outerBoundary)

	return &Built{Raw: out.Bytes(), MessageID: messageID, SubkeyID: subkeyID}, nil
}

func boundary() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return "pgpmailer-" + hex.EncodeToString(b[:]), nil
}

// normalizeNewlines converts CRLF, lone CR and lone LF to CRLF.
func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func writeBase64(w *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		w.WriteString(enc[:76])
		w.WriteString("\r\n")
		enc = enc[76:]
	}
	if len(enc) > 0 {
		w.WriteString(enc)
		w.WriteString("\r\n")
	}
}

// encodeHeader returns s as an unstructured header value. Printable ASCII is
// passed through; anything else (and anything that could be mistaken for an
// encoded-word) is emitted as folded RFC 2047 B-encoded words that never
// split a UTF-8 sequence. used is the number of columns already taken on
// the first line.
func encodeHeader(s string, used int) string {
	plain := !strings.Contains(s, "=?") && len(s)+used <= 78
	for i := 0; plain && i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			plain = false
		}
	}
	if plain {
		return s
	}
	const prefix, suffix = "=?UTF-8?B?", "?="
	const maxChunk = 39 // bytes per word: 52 Base64 chars + 12 overhead + folding
	var words []string
	for len(s) > 0 {
		n := 0
		for n < len(s) {
			_, size := utf8.DecodeRuneInString(s[n:])
			if n+size > maxChunk {
				break
			}
			n += size
		}
		words = append(words, prefix+base64.StdEncoding.EncodeToString([]byte(s[:n]))+suffix)
		s = s[n:]
	}
	return strings.Join(words, "\r\n ")
}
