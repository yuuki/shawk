package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

func TestPeers(t *testing.T) {
	p, err := ParsePeers("private,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	p.AddHost("203.0.113.9")
	for host, want := range map[string]bool{
		"127.0.0.1":    true,
		"10.1.2.3":     true,
		"172.31.0.1":   true,
		"192.168.0.1":  true,
		"100.64.0.1":   true,
		"fd00::1":      true,
		"::1":          true,
		"198.51.100.7": true,
		"203.0.113.9":  true,  // named by the user
		"db-01":        true,  // host names come from the user
		"8.8.8.8":      false, // a client on the internet
		"203.0.113.10": false,
		"2001:db8::1":  false,
	} {
		if got := p.Allow(host); got != want {
			t.Errorf("Allow(%q) = %v, want %v", host, got, want)
		}
	}
	if any, _ := ParsePeers("any"); !any.Allow("8.8.8.8") {
		t.Error(`"any" does not allow 8.8.8.8`)
	}
	if _, err := ParsePeers("10.0.0.0/33"); err == nil {
		t.Error("invalid prefix accepted")
	}
}

// fakeAgent serves /api/v1/info and records the Authorization headers.
func fakeAgent(t *testing.T, body string) (port int, auth *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	fmt.Sscan(p, &port)
	return port, &got
}

func TestTokenOnlyToAllowedPeers(t *testing.T) {
	port, auth := fakeAgent(t, `{"hostname":"a"}`)
	peers, _ := ParsePeers("10.0.0.0/8")
	c := New(port, "s3cret", time.Second, peers)

	if _, err := c.Info(context.Background(), "127.0.0.2"); !errors.Is(err, api.ErrPeerNotAllowed) {
		t.Fatalf("Info of a disallowed peer: %v", err)
	}
	if len(*auth) != 0 {
		t.Fatalf("a disallowed peer was contacted: %q", *auth)
	}
	peers.AddHost("127.0.0.1")
	if _, err := c.Info(context.Background(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if len(*auth) != 1 || (*auth)[0] != "Bearer s3cret" {
		t.Errorf("authorization = %q", *auth)
	}
}

func TestResponseLimit(t *testing.T) {
	old := maxResponse
	maxResponse = 16
	defer func() { maxResponse = old }()
	port, _ := fakeAgent(t, `{"hostname":"`+strings.Repeat("x", 100)+`"}`)
	peers, _ := ParsePeers("private")
	if _, err := New(port, "", time.Second, peers).Info(context.Background(), "127.0.0.1"); err == nil {
		t.Error("an oversized response was accepted")
	}
}
