package tracer

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// eagainReader returns EAGAIN between chunks, as a BPF iterator does after
// walking MAX_ITER_OBJECTS objects without output.
type eagainReader struct {
	chunks [][]byte
	again  bool
}

func (r *eagainReader) Read(p []byte) (int, error) {
	if r.again {
		r.again = false
		return 0, &os.PathError{Op: "read", Path: "bpf_iter", Err: unix.EAGAIN}
	}
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	r.again = true
	return n, nil
}

func TestReadIterOutputRetriesEAGAIN(t *testing.T) {
	r := &eagainReader{chunks: [][]byte{[]byte("abc"), []byte("def")}, again: true}
	got, err := readIterOutput(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Errorf("got %q", got)
	}
}
