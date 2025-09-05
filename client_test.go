package openid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientDiscover(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
		resp := map[string]string{
			"issuer":   serverURL,
			"jwks_uri": serverURL + "/keys",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	serverURL = srv.URL
	defer srv.Close()

	issuerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	c := &Client{httpClient: srv.Client()}
	doc, err := c.Discover(context.Background(), issuerURL)
	require.NoError(t, err)
	require.Equal(t, srv.URL, doc.Issuer.String())
	require.Equal(t, srv.URL+"/keys", doc.JwksURI.String())
}

func TestClientGetJwks(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := map[string]string{
				"issuer":   serverURL,
				"jwks_uri": serverURL + "/keys",
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string][]any{"keys": {}})
		default:
			http.NotFound(w, r)
		}
	}))
	serverURL = srv.URL
	defer srv.Close()

	issuerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	c := &Client{httpClient: srv.Client()}
	jwks, err := c.GetJwks(context.Background(), issuerURL)
	require.NoError(t, err)
	require.Empty(t, jwks.Keys)
}
