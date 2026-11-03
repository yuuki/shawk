package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	recListener = 1
	recOwner    = 2
)

func readIter(it *link.Iter) ([]bpfShawkIterRec, error) {
	rd, err := it.Open()
	if err != nil {
		return nil, fmt.Errorf("opening iterator: %w", err)
	}
	defer rd.Close()
	return readRecords(rd)
}

func readRecords(rd io.Reader) ([]bpfShawkIterRec, error) {
	buf, err := readIterOutput(rd)
	if err != nil {
		return nil, fmt.Errorf("reading iterator: %w", err)
	}
	return decodeRecords(buf)
}

// iterReadSize is the size of each read from an iterator. The kernel stops a
// walk whenever the buffer is full and resumes it at the next read, so a
// large buffer keeps a walk mostly uninterrupted.
const iterReadSize = 1 << 20

// readIterOutput reads an iterator to the end. A read fails with EAGAIN when
// it walked a million objects without output (MAX_ITER_OBJECTS), e.g. on a
// host with many established TCP sockets; the walk continues at the next
// read.
func readIterOutput(rd io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, iterReadSize)
	for {
		n, err := rd.Read(buf)
		out = append(out, buf[:n]...)
		switch {
		case err == io.EOF:
			return out, nil
		case errors.Is(err, unix.EAGAIN):
			continue
		case err != nil:
			return nil, err
		case n == 0:
			return out, nil
		}
	}
}

func decodeRecords(buf []byte) ([]bpfShawkIterRec, error) {
	size := binary.Size(bpfShawkIterRec{})
	if len(buf)%size != 0 {
		return nil, fmt.Errorf("iterator output has unexpected length %d", len(buf))
	}
	recs := make([]bpfShawkIterRec, len(buf)/size)
	if err := binary.Read(bytes.NewReader(buf), binary.NativeEndian, recs); err != nil {
		return nil, fmt.Errorf("decoding iterator output: %w", err)
	}
	return recs, nil
}
