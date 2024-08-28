package clialert

import (
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// SanitizeScope validates ip and range and sets the scope accordingly if it's not already set.
// The return value has consistent case.
func SanitizeScope(scope, ip, ipRange string) (string, error) {
	if ipRange != "" {
		_, _, err := net.ParseCIDR(ipRange)
		if err != nil {
			return "", fmt.Errorf("%s is not a valid range", ipRange)
		}

		if scope == "" {
			scope = types.Range
		}
	}

	if ip != "" {
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("%s is not a valid ip", ip)
		}

		if scope == "" {
			scope = types.Ip
		}
	}

	return types.NormalizeScope(scope), nil
}
