package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	expected := "test-api-key-abc123"
	headers.Set("Authorization", "ApiKey "+expected)
	
	got, err := GetAPIKey(headers)
	
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}
	
	got, err := GetAPIKey(headers)
	
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetAPIKey_EmptyHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "")
	
	got, err := GetAPIKey(headers)
	
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded for empty header, got: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetAPIKey_WrongFormat(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
	}{
		{"BearerToken", "Bearer some-token"},
		{"NoPrefix", "mykey123"},
		{"WrongPrefix", "APIKEY mykey123"},
		{"WrongPrefix2", "apikey mykey123"},
		{"WrongPrefix3", "Api-Key mykey123"},
		{"OnlyApiKey", "ApiKey"},
		{"TabSeparator", "ApiKey\tmykey123"},
		{"SpaceBefore", " ApiKey mykey123"}, // Leading space
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)
			
			got, err := GetAPIKey(headers)
			
			if err == nil {
				t.Errorf("expected error for %q", tt.authHeader)
			}
			if err != nil && err.Error() != "malformed authorization header" {
				t.Errorf("expected 'malformed authorization header' error for %q, got: %v", tt.authHeader, err)
			}
			if got != "" {
				t.Errorf("expected empty string for %q, got %q", tt.authHeader, got)
			}
		})
	}
}

func TestGetAPIKey_ValidVariations(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		expectKey  string
	}{
		{"SingleSpace", "ApiKey mykey123", "mykey123"},
		{"TrailingSpace", "ApiKey mykey123 ", "mykey123"},
		{"MultipleParts", "ApiKey mykey123 extra", "mykey123"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)
			
			got, err := GetAPIKey(headers)
			
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.authHeader, err)
			}
			if got != tt.expectKey {
				t.Errorf("expected key %q for %q, got %q", tt.expectKey, tt.authHeader, got)
			}
		})
	}
}

func TestGetAPIKey_ExtraSpacesReturnEmpty(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
	}{
		{"TwoSpaces", "ApiKey  mykey123"},
		{"ThreeSpaces", "ApiKey   mykey123"},
		{"ManySpaces", "ApiKey    mykey123"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)
			
			got, err := GetAPIKey(headers)
			
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tt.authHeader, err)
			}
			if got != "" {
				t.Errorf("expected empty string for %q, got %q", tt.authHeader, got)
			}
		})
	}
}

func TestGetAPIKey_CaseSensitive(t *testing.T) {
	headers := http.Header{}
	
	// Test that "ApiKey" must be exact case
	headers.Set("Authorization", "ApiKey correct-key")
	got, err := GetAPIKey(headers)
	if err != nil || got != "correct-key" {
		t.Errorf("exact 'ApiKey' should work: err=%v, got=%q", err, got)
	}
	
	headers.Set("Authorization", "apikey wrong-key")
	got, err = GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("lowercase 'apikey' should fail: err=%v", err)
	}
}

func TestGetAPIKey_HeaderCaseInsensitive(t *testing.T) {
	// HTTP header names are case-insensitive
	headers := http.Header{}
	expected := "test-key-123"
	
	headers.Set("authorization", "ApiKey "+expected)
	got, err := GetAPIKey(headers)
	
	if err != nil {
		t.Fatalf("expected no error with lowercase header name, got: %v", err)
	}
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestGetAPIKey_MultipleValues(t *testing.T) {
	headers := http.Header{}
	expected := "first-key"
	
	headers.Add("Authorization", "ApiKey "+expected)
	headers.Add("Authorization", "ApiKey second-key")
	
	got, err := GetAPIKey(headers)
	
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != expected {
		t.Errorf("expected first value %q, got %q", expected, got)
	}
}
