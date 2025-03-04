package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	_password = "rec_account@password#2020"
)

func TestHashPasswordAndVerifyPasswordHash(t *testing.T) {
	hash, err := HashPassword(_password)
	assert.Nil(t, err)

	ret, err := VerifyPasswordHash(_password, hash)
	assert.Nil(t, err)
	assert.True(t, ret)
}

func TestHashPassword(t *testing.T) {
	t.Run("normal password", func(t *testing.T) {
		password := "securePassword123!"
		hash, err := HashPassword(password)
		assert.Nil(t, err)

		assert.True(t, strings.HasPrefix(hash, "argon2id$"))

		valid, err := VerifyPasswordHash(password, hash)
		assert.Nil(t, err)
		assert.True(t, valid)
	})

	t.Run("empty password", func(t *testing.T) {
		_, err := HashPassword("")
		assert.Error(t, err)
	})
}

func TestVerifyPasswordHash(t *testing.T) {
	testCases := []struct {
		name        string
		password    string
		encodedHash string
		expectValid bool
		expectError bool
	}{
		{
			name:        "valid hash",
			password:    "correctPassword",
			encodedHash: "argon2id$1$65536$4$LacUZh4Butc7x7cCNatqQA$keqWprxT0fZODrVILQT7cn3NsHGkCiQ9gkWSb6f5alY",
			expectValid: true,
		},
		{
			name:        "invalid password",
			password:    "wrongPassword",
			encodedHash: "argon2id$1$65536$4$LacUZh4Butc7x7cCNatqQA$keqWprxT0fZODrVILQT7cn3NsHGkCiQ9gkWSb6f5alY",
			expectValid: false,
		},
		{
			name:        "invalid hash format",
			password:    "password",
			encodedHash: "invalid_hash",
			expectError: true,
		},
		{
			name:        "invalid parameters",
			password:    "password",
			encodedHash: "argon2id$invalid$65536$4$c2Fs0$hash",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := VerifyPasswordHash(tc.password, tc.encodedHash)
			assert.Equal(t, tc.expectError, err != nil)
			if !tc.expectError {
				assert.Nil(t, err)
				assert.Equal(t, tc.expectValid, valid)
			}
		})
	}
}

func TestHashPasswordWithParams(t *testing.T) {
	testParams := []*Argon2Params{
		{Time: 2, Memory: 131072, Threads: 2, SaltLen: 8, KeyLen: 16},
		{Time: 1, Memory: 32768, Threads: 1, SaltLen: 32, KeyLen: 64},
	}

	for _, params := range testParams {
		t.Run("custom parameters", func(t *testing.T) {
			hash, err := HashPasswordWithParams("testPassword", params)
			if err != nil {
				t.Fatalf("Hash failed: %v", err)
			}

			// Verify with original parameters
			valid, err := VerifyPasswordHash("testPassword", hash)
			if err != nil {
				t.Fatalf("Verification failed: %v", err)
			}
			if !valid {
				t.Error("Valid password verification failed")
			}
		})
	}
}

func TestGenerateSalt_EdgeCases(t *testing.T) {
	testCases := []struct {
		name   string
		length uint32
		valid  bool
	}{
		{"zero length", 0, false},
		{"max length", 1 << 20, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			salt, err := generateSalt(tc.length)
			assert.Equal(t, tc.valid, err == nil)
			assert.Equal(t, len(salt), int(tc.length))
		})
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "benchmarkPassword123!"

	b.Run("default params", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = HashPassword(password)
		}
	})

	b.Run("high cost params", func(b *testing.B) {
		params := &Argon2Params{
			Time:    3,
			Memory:  131072,
			Threads: 2,
			SaltLen: 32,
			KeyLen:  64,
		}
		for i := 0; i < b.N; i++ {
			_, _ = HashPasswordWithParams(password, params)
		}
	})
}

func BenchmarkVerifyPasswordHash(b *testing.B) {
	password := "benchmarkPassword123!"
	hash, _ := HashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyPasswordHash(password, hash)
	}
}
