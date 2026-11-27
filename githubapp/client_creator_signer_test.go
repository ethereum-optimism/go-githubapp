// Copyright 2026 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package githubapp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type recordingSigner struct {
	mu     sync.Mutex
	issuer []string
}

func (s *recordingSigner) Sign(claims jwt.Claims) (string, error) {
	registered, ok := claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", fmt.Errorf("unexpected claims type %T", claims)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issuer = append(s.issuer, registered.Issuer)
	return "signed-by-test-signer", nil
}

func (s *recordingSigner) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.issuer...)
}

func newSignerTestServer(t *testing.T) (*httptest.Server, *sync.Map) {
	t.Helper()

	var auth sync.Map
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		auth.Store("/app", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id": 1, "slug": "test-app"}`)
	})
	mux.HandleFunc("/app/installations/42/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		auth.Store("/app/installations/42/access_tokens", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token": "installation-token", "expires_at": %q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	})
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		auth.Store("/repos/o/r", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id": 2, "name": "r"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &auth
}

func loadAuth(t *testing.T, auth *sync.Map, path string) string {
	t.Helper()
	v, ok := auth.Load(path)
	if !ok {
		t.Fatalf("no request recorded for %s", path)
	}
	return v.(string)
}

func TestWithSignerAppClient(t *testing.T) {
	srv, auth := newSignerTestServer(t)
	signer := &recordingSigner{}

	cc := NewClientCreator(srv.URL, srv.URL+"/graphql", 1234, nil, WithSigner(signer))

	client, err := cc.NewAppClient()
	if err != nil {
		t.Fatalf("unexpected error creating app client: %v", err)
	}
	if _, _, err := client.Apps.Get(context.Background(), ""); err != nil {
		t.Fatalf("unexpected error getting app: %v", err)
	}

	if got := loadAuth(t, auth, "/app"); got != "Bearer signed-by-test-signer" {
		t.Errorf("incorrect authorization header: %q", got)
	}
	if calls := signer.calls(); len(calls) != 1 || calls[0] != "1234" {
		t.Errorf("signer called with unexpected issuers: %v", calls)
	}
}

func TestWithSignerInstallationClient(t *testing.T) {
	srv, auth := newSignerTestServer(t)
	signer := &recordingSigner{}

	cc := NewClientCreator(srv.URL, srv.URL+"/graphql", 1234, nil, WithSigner(signer))

	client, err := cc.NewInstallationClient(42)
	if err != nil {
		t.Fatalf("unexpected error creating installation client: %v", err)
	}
	if _, _, err := client.Repositories.Get(context.Background(), "o", "r"); err != nil {
		t.Fatalf("unexpected error getting repository: %v", err)
	}

	if got := loadAuth(t, auth, "/app/installations/42/access_tokens"); got != "Bearer signed-by-test-signer" {
		t.Errorf("incorrect authorization header for token request: %q", got)
	}
	if got := loadAuth(t, auth, "/repos/o/r"); got != "token installation-token" {
		t.Errorf("incorrect authorization header for API request: %q", got)
	}
	if calls := signer.calls(); len(calls) != 1 || calls[0] != "1234" {
		t.Errorf("signer called with unexpected issuers: %v", calls)
	}
}

func TestWithoutSignerRequiresPrivateKey(t *testing.T) {
	cc := NewClientCreator("https://api.github.com/", "https://api.github.com/graphql", 1234, nil)

	if _, err := cc.NewAppClient(); err == nil {
		t.Error("expected an error creating an app client without a private key or signer")
	}
	if _, err := cc.NewInstallationClient(42); err == nil {
		t.Error("expected an error creating an installation client without a private key or signer")
	}
}
