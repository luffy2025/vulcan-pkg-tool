package password

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/vulcan-frame/vulcan-pkg-tool/rand"
	"golang.org/x/crypto/argon2"
)

// 定义错误类型
const (
	ErrInvalidHashFormat    = "invalid hash format"
	ErrUnsupportedAlgorithm = "unsupported algorithm"
	ErrParameterConversion  = "parameter conversion error"
)

type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

var DefaultArgon2Params = Argon2Params{
	Time:    1,
	Memory:  65536,
	Threads: 4,
	SaltLen: 16,
	KeyLen:  32,
}

func HashPassword(password string) (string, error) {
	return HashPasswordWithParams(password, &DefaultArgon2Params)
}

func HashPasswordWithParams(password string, params *Argon2Params) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}

	salt, err := generateSalt(params.SaltLen)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s",
		params.Time,
		params.Memory,
		params.Threads,
		b64Salt,
		b64Hash), nil
}

func VerifyPasswordHash(password, encodedHash string) (bool, error) {
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		uint32(len(hash)),
	)

	return bytes.Equal(computedHash, hash), nil
}

func generateSalt(length uint32) ([]byte, error) {
	if length == 0 {
		return nil, errors.New("salt length must be greater than 0")
	}

	salt, err := rand.RandomBytes(int(length))
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func decodeHash(encodedHash string) (*Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return nil, nil, nil, errors.New(ErrInvalidHashFormat)
	}

	var params Argon2Params
	var err error

	if params.Time, err = parseUint32(parts[1]); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: time: %w", ErrParameterConversion, err)
	}
	if params.Memory, err = parseUint32(parts[2]); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: memory: %w", ErrParameterConversion, err)
	}
	if params.Threads, err = parseUint8(parts[3]); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: threads: %w", ErrParameterConversion, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	return &params, salt, hash, nil
}

// Helper functions for safe numeric conversions
func parseUint32(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func parseUint8(s string) (uint8, error) {
	v, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(v), nil
}
