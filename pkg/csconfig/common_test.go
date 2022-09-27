package csconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func TestLoadCommon(t *testing.T) {
	pidDirPath := "./tests"
	LogDirFullPath, err := filepath.Abs("./tests/log/")
	require.NoError(t, err)

	WorkingDirFullPath, err := filepath.Abs("./tests")
	require.NoError(t, err)

	tests := []struct {
		name        string
		Input       *csconfig.Config
		expected    *csconfig.CommonCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				Common: &csconfig.CommonCfg{
					Daemonize:  true,
					PidDir:     "./tests",
					LogMedia:   "file",
					LogDir:     "./tests/log/",
					WorkingDir: "./tests/",
				},
			},
			expected: &csconfig.CommonCfg{
				Daemonize:  true,
				PidDir:     pidDirPath,
				LogMedia:   "file",
				LogDir:     LogDirFullPath,
				WorkingDir: WorkingDirFullPath,
			},
		},
		{
			name: "empty working dir",
			Input: &csconfig.Config{
				Common: &csconfig.CommonCfg{
					Daemonize: true,
					PidDir:    "./tests",
					LogMedia:  "file",
					LogDir:    "./tests/log/",
				},
			},
			expected: &csconfig.CommonCfg{
				Daemonize: true,
				PidDir:    pidDirPath,
				LogMedia:  "file",
				LogDir:    LogDirFullPath,
			},
		},
		{
			name:           "no common",
			Input:          &csconfig.Config{},
			expectedErr:    "no common block provided in configuration file",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadCommon()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expected, tc.Input.Common)
		})
	}
}
