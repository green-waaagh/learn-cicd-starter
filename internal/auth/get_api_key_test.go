package auth_test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "ApiKey secret-token")

	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if apiKey != "secret-token" {
		t.Fatalf("expected api key 'secret-token', got '%s'", apiKey)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = auth.GetAPIKey(req.Header)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetAPIKey_InvalidFormat(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer secret-token")

	_, err = auth.GetAPIKey(req.Header)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
