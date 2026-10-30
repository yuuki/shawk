// Package client talks to shawk agents.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

// Client queries agents. An agent is addressed by the host name or address
// of the host it runs on; the API port is common to all agents.
type Client struct {
	Port    int
	Token   string
	Timeout time.Duration
	http    *http.Client

	mu    sync.Mutex
	infos map[string]infoResult
}

type infoResult struct {
	info *api.Info
	err  error
}

// New returns a client.
func New(port int, token string, timeout time.Duration) *Client {
	return &Client{
		Port:    port,
		Token:   token,
		Timeout: timeout,
		http:    &http.Client{Timeout: timeout},
		infos:   map[string]infoResult{},
	}
}

func (c *Client) get(ctx context.Context, host, path string, query url.Values, out any) error {
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(c.Port)), Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s: %s: %s", u.Host, resp.Status, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Info returns the information of the agent on host. Results, including
// failures, are cached for the lifetime of the client.
func (c *Client) Info(ctx context.Context, host string) (*api.Info, error) {
	c.mu.Lock()
	r, ok := c.infos[host]
	c.mu.Unlock()
	if ok {
		return r.info, r.err
	}
	var info api.Info
	err := c.get(ctx, host, "/api/v1/info", nil, &info)
	r = infoResult{err: err}
	if err == nil {
		r.info = &info
	}
	c.mu.Lock()
	c.infos[host] = r
	c.mu.Unlock()
	return r.info, r.err
}

// Edges returns the edges recorded by the agent on host.
func (c *Client) Edges(ctx context.Context, host string, q api.EdgeQuery) ([]api.Edge, error) {
	var resp api.EdgesResponse
	if err := c.get(ctx, host, "/api/v1/edges", q.Values(), &resp); err != nil {
		return nil, err
	}
	return resp.Edges, nil
}

// Listeners returns the listeners recorded by the agent on host.
func (c *Client) Listeners(ctx context.Context, host string, since time.Time) ([]api.Listener, error) {
	v := url.Values{}
	if !since.IsZero() {
		v.Set("since", since.UTC().Format(time.RFC3339))
	}
	var resp api.ListenersResponse
	if err := c.get(ctx, host, "/api/v1/listeners", v, &resp); err != nil {
		return nil, err
	}
	return resp.Listeners, nil
}

// Programs returns the run time statistics of the BPF programs of an agent.
func (c *Client) Programs(ctx context.Context, host string) ([]map[string]any, error) {
	var out []map[string]any
	err := c.get(ctx, host, "/api/v1/programs", nil, &out)
	return out, err
}
