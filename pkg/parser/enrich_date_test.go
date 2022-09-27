package parser_test

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestDateParse(t *testing.T) {
	tests := []struct {
		name            string
		evt             types.Event
		expectedErr     string
		expectedStrTime *string
	}{
		{
			name: "RFC3339",
			evt: types.Event{
				StrTime: "2019-10-12T07:20:50.52Z",
			},
			expectedErr:     "",
			expectedStrTime: types.StrPtr("2019-10-12T07:20:50.52Z"),
		},
		{
			name: "02/Jan/2006:15:04:05 -0700",
			evt: types.Event{
				StrTime: "02/Jan/2006:15:04:05 -0700",
			},
			expectedErr:     "",
			expectedStrTime: types.StrPtr("2006-01-02T15:04:05-07:00"),
		},
		{
			name: "Dec 17 08:17:43",
			evt: types.Event{
				StrTime:       "2011 X 17 zz 08X17X43 oneone Dec",
				StrTimeFormat: "2006 X 2 zz 15X04X05 oneone Jan",
			},
			expectedErr:     "",
			expectedStrTime: types.StrPtr("2011-12-17T08:17:43Z"),
		},
	}

	logger := log.WithFields(log.Fields{
		"test": "test",
	})

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			strTime, err := parser.ParseDate(tc.evt.StrTime, &tc.evt, nil, logger)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			if tc.expectedStrTime != nil {
				require.Equal(t, *tc.expectedStrTime, strTime["MarshaledTime"])
			}
		})
	}
}
