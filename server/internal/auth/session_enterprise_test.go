package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func enterpriseClaims(t *testing.T, sub, sid string, ver int64) jwt.MapClaims {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":                  sub,
		"email":                sub + "@example.com",
		EnterpriseSessionClaim: sid,
		EnterpriseVersionClaim: ver,
		"exp":                  time.Now().Add(time.Hour).Unix(),
	}).SignedString(JWTSecret())
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	claims, err := ParseSessionToken(signed)
	if err != nil {
		t.Fatalf("parse seed token: %v", err)
	}
	return claims
}

func TestRenewSessionTokenCopiesEnterpriseClaimsWithoutRefresher(t *testing.T) {
	claims := enterpriseClaims(t, "user-1", "sid-9", 7)
	token, _, err := RenewSessionToken(claims)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed, err := ParseSessionToken(token)
	if err != nil {
		t.Fatalf("parse renewed: %v", err)
	}
	if got := renewed[EnterpriseSessionClaim]; got != "sid-9" {
		t.Fatalf("ent_sid = %v, want sid-9", got)
	}
	if got := renewed[EnterpriseVersionClaim]; got != float64(7) {
		t.Fatalf("ent_ver = %v, want 7", got)
	}
}

func TestRenewSessionTokenWithEnterpriseRefreshesVersion(t *testing.T) {
	claims := enterpriseClaims(t, "user-1", "sid-9", 7)
	refresh := func(userID string) (string, int64, bool) {
		if userID != "user-1" {
			t.Fatalf("refresher user = %q", userID)
		}
		return "sid-10", 42, true
	}
	token, _, err := RenewSessionTokenWithEnterprise(claims, refresh)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed, err := ParseSessionToken(token)
	if err != nil {
		t.Fatalf("parse renewed: %v", err)
	}
	if got := renewed[EnterpriseSessionClaim]; got != "sid-10" {
		t.Fatalf("ent_sid = %v, want refreshed sid-10", got)
	}
	if got := renewed[EnterpriseVersionClaim]; got != float64(42) {
		t.Fatalf("ent_ver = %v, want refreshed 42", got)
	}
}

func TestRenewSessionTokenDropsEnterpriseClaimsWhenIdentityGone(t *testing.T) {
	claims := enterpriseClaims(t, "user-1", "sid-9", 7)
	token, _, err := RenewSessionTokenWithEnterprise(claims, func(string) (string, int64, bool) {
		return "", 0, false
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed, err := ParseSessionToken(token)
	if err != nil {
		t.Fatalf("parse renewed: %v", err)
	}
	if _, ok := renewed[EnterpriseSessionClaim]; ok {
		t.Fatal("ent_sid survived renewal for a non-enterprise user")
	}
	if _, ok := renewed[EnterpriseVersionClaim]; ok {
		t.Fatal("ent_ver survived renewal for a non-enterprise user")
	}
	if renewed["sub"] != "user-1" {
		t.Fatalf("sub = %v, want user-1", renewed["sub"])
	}
}

func TestRenewSessionTokenPersonalUnchanged(t *testing.T) {
	signed, _, err := renewSessionToken(jwt.MapClaims{
		"sub": "user-2", "exp": time.Now().Add(time.Hour).Unix(),
	}, nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	claims, err := ParseSessionToken(signed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	token, _, err := RenewSessionTokenWithEnterprise(claims, func(string) (string, int64, bool) {
		t.Fatal("refresher must not run for personal sessions with nil refresher")
		return "", 0, false
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed, err := ParseSessionToken(token)
	if err != nil {
		t.Fatalf("parse renewed: %v", err)
	}
	if _, ok := renewed[EnterpriseSessionClaim]; ok {
		t.Fatal("personal token gained enterprise claims")
	}
}
