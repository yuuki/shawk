package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// These fuzz targets need no root: they decode what the BPF programs write,
// not what a kernel does.

// unescapeUnixName is the inverse of UnixName, for the tests.
func unescapeUnixName(name string) ([]byte, error) {
	var out []byte
	if rest, ok := strings.CutPrefix(name, "@"); ok {
		out = append(out, 0)
		name = rest
	}
	for name != "" {
		if name[0] != '\\' {
			out = append(out, name[0])
			name = name[1:]
			continue
		}
		switch {
		case strings.HasPrefix(name, `\\`):
			out = append(out, '\\')
			name = name[2:]
		case strings.HasPrefix(name, `\x`) && len(name) >= 4:
			b, err := strconv.ParseUint(name[2:4], 16, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(b))
			name = name[4:]
		default:
			return nil, errors.New("a backslash that starts no escape")
		}
	}
	return out, nil
}

// FuzzUnixName checks that the name of any sun_path is valid UTF-8 of
// printable characters, starts with @ exactly for an abstract name, and
// tells the bytes of the socket apart from those of any other: the
// connector keeps it as a label and PostgreSQL as text.
func FuzzUnixName(f *testing.F) {
	for _, s := range []string{
		"/run/postgresql/.s.PGSQL.5432", "/run/docker.sock", "\x00app/control", "\x00\x00", "@app", `C:\path`,
		"caf\xc3\xa9", "\xe3\x83", "\xff\xfe", "tab\tnew\nline", "\u00a0nbsp", "\u200bzero-width", "\x00", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		name := UnixName(b)
		if !utf8.ValidString(name) {
			t.Fatalf("UnixName(%q) = %q, not valid UTF-8", b, name)
		}
		for _, r := range name {
			if !unicode.IsPrint(r) {
				t.Fatalf("UnixName(%q) = %q has the unprintable %U", b, name, r)
			}
		}
		if abstract := len(b) > 0 && b[0] == 0; abstract != strings.HasPrefix(name, "@") {
			t.Fatalf("UnixName(%q) = %q: abstract %v", b, name, abstract)
		}
		got, err := unescapeUnixName(name)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("UnixName(%q) = %q, which unescapes to %q (%v)", b, name, got, err)
		}
	})
}

// FuzzDecodeRecords checks the decoding of the output of the iterators:
// whole records only, decoded without loss, and the names of their Unix
// sockets within sun_path.
func FuzzDecodeRecords(f *testing.F) {
	size := binary.Size(bpfShawkIterRec{})
	listener := bpfShawkIterRec{Type: recListener, Proto: uint8(ProtoTCP), Port: 5432, Netns: 4026531840, Pid: 42}
	copy(listener.Addr[:], []byte{10: 0xff, 11: 0xff, 12: 10, 15: 1})
	for i, c := range "postgres" {
		listener.Comm[i] = int8(c)
	}
	unix := bpfShawkIterRec{Type: recOwner, Proto: uint8(ProtoUnix), PathLen: 6, Ino: 1234}
	for i, c := range "\x00x/sck" {
		unix.Path[i] = int8(c)
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, []bpfShawkIterRec{listener, unix}); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add(buf.Bytes()[:size+1])
	f.Add(make([]byte, size))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		recs, err := decodeRecords(b)
		if len(b)%size != 0 {
			if err == nil {
				t.Fatalf("%d bytes, not whole records of %d, decoded", len(b), size)
			}
			return
		}
		if err != nil || len(recs) != len(b)/size {
			t.Fatalf("%d bytes: %d records, %v", len(b), len(recs), err)
		}
		var again bytes.Buffer
		if err := binary.Write(&again, binary.NativeEndian, recs); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again.Bytes(), b) {
			t.Fatal("the records do not encode to the bytes they were decoded from")
		}
		for i := range recs {
			p := recPath(&recs[i])
			if len(p) > len(recs[i].Path) || len(p) > int(recs[i].PathLen) {
				t.Fatalf("record %d: path of %d bytes, path_len %d", i, len(p), recs[i].PathLen)
			}
			if name := UnixName(p); !utf8.ValidString(name) {
				t.Fatalf("record %d: name %q", i, name)
			}
		}
	})
}
