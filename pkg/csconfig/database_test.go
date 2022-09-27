package csconfig_test

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLoadDBConfig(t *testing.T) {
	tests := []struct {
		name        string
		Input       *csconfig.Config
		expected    *csconfig.DatabaseCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				DbConfig: &csconfig.DatabaseCfg{
					Type:         "sqlite",
					DbPath:       "./tests/test.db",
					MaxOpenConns: types.IntPtr(10),
				},
				Cscli: &csconfig.CscliCfg{},
				API: &csconfig.APICfg{
					Server: &csconfig.LocalApiServerCfg{},
				},
			},
			expected: &csconfig.DatabaseCfg{
				Type:         "sqlite",
				DbPath:       "./tests/test.db",
				MaxOpenConns: types.IntPtr(10),
			},
		},
		{
			name:        "no configuration path",
			Input:       &csconfig.Config{},
			expectedErr: "no database configuration provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadDBConfig()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expected != nil {
				return
			}

			require.Equal(t, tc.expected, tc.Input.DbConfig)
		})
	}
}
