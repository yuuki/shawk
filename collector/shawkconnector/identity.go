package shawkconnector

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
)

// Values of host_identity.
const (
	// hostIdentityNone trusts the host.name and host.id that agents send.
	hostIdentityNone = "none"
	// hostIdentityCertificate accepts the metrics of a host only from an
	// agent whose verified client certificate names it.
	hostIdentityCertificate = "certificate"
)

var errNoClientCertificate = errors.New("the request did not come over gRPC with a verified client certificate")

// clientCertificate returns the verified client certificate of the
// request of ctx: the receiver passes the context of its gRPC call on, with
// the peer and its TLS state. A request over HTTP carries neither.
func clientCertificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := grpcpeer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, errNoClientCertificate
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.PeerCertificates) == 0 {
		return nil, errNoClientCertificate
	}
	return info.State.PeerCertificates[0], nil
}

// certificateNames returns the names a certificate gives its holder: its
// DNS names, or its common name when it has none.
func certificateNames(cert *x509.Certificate) []string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames
	}
	if cert.Subject.CommonName != "" {
		return []string{cert.Subject.CommonName}
	}
	return nil
}

// certifiedHost checks that a certificate names the host: one of its names
// equals host.name, ignoring case and a final dot. Wildcards are not
// expanded, so that a certificate stands for one host.
func certifiedHost(cert *x509.Certificate, hostname string) error {
	h := strings.TrimSuffix(hostname, ".")
	names := certificateNames(cert)
	for _, n := range names {
		if h != "" && strings.EqualFold(strings.TrimSuffix(n, "."), h) {
			return nil
		}
	}
	return fmt.Errorf("the client certificate names %q, not the host %q", names, hostname)
}

// certificateID identifies a client certificate by the SHA-256 of its DER
// encoding, which `openssl x509 -fingerprint -sha256` prints with colons:
// a certificate stands for one host, whatever names it has.
func certificateID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// cleanString makes a string from an agent acceptable to PostgreSQL, which
// refuses text with NUL or that is not valid UTF-8, and to what shows it:
// such bytes become U+FFFD, as the agent replaces them, and so do the
// control characters, the separators of lines and paragraphs and the
// characters that turn the direction of a text around. A name is what a
// process declares (docs/design.md §4.1), and it becomes a label of
// Prometheus and a part of the text of an alert, where a line break would
// add lines that the alert did not write.
func cleanString(s string) string {
	if pgText(s) && !strings.ContainsFunc(s, hiddenRune) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if hiddenRune(r) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}

// pgClean makes a text acceptable to PostgreSQL, and no more: free text
// that an operator wrote, as the reason of a node state, or the message
// of an error, keeps its line breaks.
func pgClean(s string) string {
	if pgText(s) {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "�")
}

// hiddenRune tells the characters that cleanString replaces: the controls
// (NUL, line breaks, escape, U+0080 to U+009F), U+2028 and U+2029, and
// the marks of the direction of a text (U+202A to U+202E, U+2066 to
// U+2069).
func hiddenRune(r rune) bool {
	return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// pgText tells whether PostgreSQL accepts a string as text: valid UTF-8
// without NUL. The names of the configuration are checked with it rather
// than cleaned: the collector then refuses to start and tells what to fix,
// where a cleaned name would differ from the one configured.
func pgText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
