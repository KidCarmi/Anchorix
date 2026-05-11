//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct-horse-battery-staple"
)

func seedAdmin(t *testing.T, svc *auth.Service) *auth.User {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, err := svc.CreateUser(ctx, "anchorix", testEmail, "Alice", testPassword, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("seedAdmin: %v", err)
	}
	return u
}

func TestLoginMeLogoutRoundTrip(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	user := seedAdmin(t, svc)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// 1. Login.
	body := strings.NewReader(`{"email":"` + testEmail + `","password":"` + testPassword + `"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login status = %d; body=%s", resp.StatusCode, b)
	}
	var loginOut auth.User
	if err := json.NewDecoder(resp.Body).Decode(&loginOut); err != nil {
		resp.Body.Close()
		t.Fatalf("decode login: %v", err)
	}
	resp.Body.Close()
	if loginOut.ID != user.ID {
		t.Fatalf("login returned user id %q; want %q", loginOut.ID, user.ID)
	}

	// 2. /me with cookie returns the same user.
	resp, err = client.Get(srv.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatalf("/me: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("/me status = %d; body=%s", resp.StatusCode, b)
	}
	var meOut auth.User
	if err := json.NewDecoder(resp.Body).Decode(&meOut); err != nil {
		resp.Body.Close()
		t.Fatalf("decode /me: %v", err)
	}
	resp.Body.Close()
	if meOut.Email != testEmail {
		t.Fatalf("/me email = %q; want %q", meOut.Email, testEmail)
	}

	// 3. Logout returns 204.
	resp, err = client.Post(srv.URL+"/api/v1/auth/logout", "", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d; want 204", resp.StatusCode)
	}

	// 4. /me after logout returns 401 with the canonical envelope.
	resp, err = client.Get(srv.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatalf("/me after logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after logout status = %d; want 401", resp.StatusCode)
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errEnv); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errEnv.Error.Code == "" {
		t.Fatal("error envelope missing code")
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	_ = seedAdmin(t, svc)

	body := strings.NewReader(`{"email":"` + testEmail + `","password":"wrong"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
	var errEnv struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errEnv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errEnv.Error.Code != "invalid_credentials" {
		t.Fatalf("error code = %q; want invalid_credentials", errEnv.Error.Code)
	}
}

func TestMeRequiresAuth(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	resp, err := http.Get(srv.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatalf("/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}
