package csconfig

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLoadDBConfig(t *testing.T) {
	tests := []struct {
		name           string
		Input          *Config
		expectedResult *DatabaseCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				DbConfig: &DatabaseCfg{
					Type:         "sqlite",
					DbPath:       "./tests/test.db",
					MaxOpenConns: types.IntPtr(10),
				},
				Cscli: &CscliCfg{},
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
			},
			expectedResult: &DatabaseCfg{
				Type:         "sqlite",
				DbPath:       "./tests/test.db",
				MaxOpenConns: types.IntPtr(10),
			},
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadDBConfig()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedResult != nil {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.DbConfig)
		})
	}
}
