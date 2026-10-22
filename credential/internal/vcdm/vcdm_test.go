package vcdm

import (
	"strings"
	"testing"
	"time"
)

func TestCheckValidityPeriod(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }

	cases := []struct {
		name       string
		validFrom  string
		validUntil string
		leeway     time.Duration
		wantErr    string
	}{
		{name: "no window"},
		{name: "inside the window", validFrom: at(-time.Hour), validUntil: at(time.Hour)},
		{name: "not valid yet", validFrom: at(5 * time.Second), wantErr: "credential is not valid yet"},
		{name: "expired", validUntil: at(-5 * time.Second), wantErr: "credential is expired"},
		{name: "validFrom ahead, within leeway", validFrom: at(5 * time.Second), leeway: 10 * time.Second},
		{name: "validFrom ahead, beyond leeway", validFrom: at(15 * time.Second), leeway: 10 * time.Second, wantErr: "credential is not valid yet"},
		{name: "validUntil passed, within leeway", validUntil: at(-5 * time.Second), leeway: 10 * time.Second},
		{name: "validUntil passed, beyond leeway", validUntil: at(-15 * time.Second), leeway: 10 * time.Second, wantErr: "credential is expired"},
		{name: "unparsable validFrom", validFrom: "yesterday", wantErr: "failed to parse validFrom"},
		{name: "unparsable validUntil", validUntil: "tomorrow", wantErr: "failed to parse validUntil"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckValidityPeriod("credential", tc.validFrom, tc.validUntil, tc.leeway)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
