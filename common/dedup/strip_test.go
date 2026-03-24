package dedup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripDynamicTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "hex token removal",
			input: `<div>session=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4</div>`,
			want:  `<div>session=</div>`,
		},
		{
			name:  "long hex token removal",
			input: `token: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6`,
			want:  `token: `,
		},
		{
			name:  "short hex string unchanged",
			input: `color: #ff00ff; id: abc123`,
			want:  `color: #ff00ff; id: abc123`,
		},
		{
			name:  "timestamp removal",
			input: `<span>Last updated: 2024-01-15T09:30:00Z</span>`,
			want:  `<span>Last updated: Z</span>`,
		},
		{
			name:  "multiple timestamps",
			input: `start: 2024-01-15T09:30:00, end: 2024-12-31T23:59:59`,
			want:  `start: , end: `,
		},
		{
			name:  "csrf attribute stripping",
			input: `<input name="csrf_token" value="abc123xyz"/>`,
			want:  `<input />`,
		},
		{
			name:  "nonce attribute stripping",
			input: `<input id="nonce" value="random-value-here"/>`,
			want:  `<input />`,
		},
		{
			name:  "token attribute stripping",
			input: `<input name="token" value="s3cr3t"/>`,
			want:  `<input />`,
		},
		{
			name:  "content without tokens passes through unchanged",
			input: `<html><body><h1>Hello World</h1><p>Simple page</p></body></html>`,
			want:  `<html><body><h1>Hello World</h1><p>Simple page</p></body></html>`,
		},
		{
			name:  "combined stripping",
			input: `<html><span>2024-01-15T09:30:00</span><input name="csrf_token" value="xyz"/><div>a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4</div></html>`,
			want:  `<html><span></span><input /><div></div></html>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripDynamicTokens([]byte(tt.input))
			assert.Equal(t, tt.want, string(got))
		})
	}
}
