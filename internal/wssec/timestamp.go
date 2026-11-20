package wssec

import (
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2/wss"
)

// timestampFresh is called only after exact-node signature coverage succeeds.
// Receive tolerance never inherits the outbound Timestamp clock offset.
func timestampFresh(stamp *xdm.Node, now time.Time, policy ReceivePolicy) bool {
	if stamp == nil || policy.ClockSkewSeconds < 0 || policy.ClockSkewSeconds > 300 || policy.MaxAgeSeconds < 1 || policy.MaxAgeSeconds > 3600 {
		return false
	}
	ts, err := wss.ParseTimestamp(stamp)
	if err != nil || ts.Expires.IsZero() || !ts.Expires.After(ts.Created) {
		return false
	}
	// The provider validates field order, uniqueness, UTC syntax and ValueType.
	// Created/Expires must also be scalar values, not nested element string-values.
	for field := range stamp.Children() {
		if field.Kind() == xdm.KindText && strings.Trim(field.StringValue(), " \t\r\n") != "" {
			return false
		}
		if field.Kind() == xdm.KindElement {
			for c := range field.Children() {
				if c.Kind() == xdm.KindElement {
					return false
				}
			}
		}
	}
	maxAge := time.Duration(policy.MaxAgeSeconds) * time.Second
	skew := time.Duration(policy.ClockSkewSeconds) * time.Second
	return ts.Expires.Sub(ts.Created) <= maxAge && ts.Check(now, skew, maxAge) == nil
}
