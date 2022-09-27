package csconfig_test

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/stretchr/testify/require"
)

func TestLoadPrometheus(t *testing.T) {
	tests := []struct {
		name           string
		Input          *csconfig.Config
		expectedResult string
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				Prometheus: &csconfig.PrometheusCfg{
					Enabled:    true,
					Level:      "full",
					ListenAddr: "127.0.0.1",
					ListenPort: 6060,
				},
				Cscli: &csconfig.CscliCfg{},
			},
			expectedResult: "http://127.0.0.1:6060",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadPrometheus()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.Cscli.PrometheusUrl)
		})
	}
}
