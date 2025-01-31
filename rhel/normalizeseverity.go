package rhel

import (
	"strings"

	"github.com/quay/claircore"
)

const (
	None      = "none"
	Low       = "low"
	Moderate  = "moderate"
	Important = "important"
	Critical  = "critical"
)

func NormalizeSeverity(severity string) claircore.Severity {
	switch strings.ToLower(severity) {
	case None:
		return claircore.Unknown
	case Low:
		return claircore.Low
	case Moderate:
		return claircore.Medium
	case Important:
		return claircore.High
	case Critical:
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
