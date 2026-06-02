package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Session represents an authenticated user session.
type Session struct {
	Sub    string    // unique identifier (subject) from the OIDC provider
	Email  string    // user email
	Expiry time.Time // expiry time
}

const sessionCookie = "multirepo_session"
const stateCookie = "multirepo_oidc_state"

// encode serializes the session into a signed HMAC-SHA256 cookie value.
// Format: base64url(sub|email|expiry_unix) . hex(hmac)
func (s Session) encode(secret string) string {
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(s.Sub + "|" + s.Email + "|" + strconv.FormatInt(s.Expiry.Unix(), 10)),
	)
	sig := sign(payload, secret)
	return payload + "." + sig
}

// decodeSession parses and verifies a session cookie.
func decodeSession(value, secret string) (*Session, error) {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok {
		return nil, fmt.Errorf("invalid session format")
	}
	if sig != sign(payload, secret) {
		return nil, fmt.Errorf("invalid session signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("corrupted session")
	}

	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("corrupted session")
	}

	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid session expiry")
	}

	s := &Session{
		Sub:    parts[0],
		Email:  parts[1],
		Expiry: time.Unix(exp, 0),
	}
	if time.Now().After(s.Expiry) {
		return nil, fmt.Errorf("session expired")
	}
	return s, nil
}

func sign(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload)) //nolint:errcheck
	return hex.EncodeToString(mac.Sum(nil))
}
