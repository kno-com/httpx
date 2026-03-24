package httpx

import (
	"context"
	"testing"
	"time"
)

func TestDialUTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialUTLS(ctx, "tcp", "www.google.com:443")
	if err != nil {
		t.Fatalf("dialUTLS failed: %v", err)
	}
	defer conn.Close()

	// Verify the connection is usable by checking remote address.
	if conn.RemoteAddr() == nil {
		t.Fatal("expected non-nil remote address")
	}
}
