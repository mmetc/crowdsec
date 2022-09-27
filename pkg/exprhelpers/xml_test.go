package exprhelpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXMLGetAttributeValue(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name      string
		xmlString string
		path      string
		attribute string
		expected  string
	}{
		{
			name:      "XMLGetAttributeValue",
			xmlString: `<root><child attr="value"/></root>`,
			path:      "/root/child",
			attribute: "attr",
			expected:  "value",
		},
		{
			name:      "Non existing attribute for XMLGetAttributeValue",
			xmlString: `<root><child attr="value"/></root>`,
			path:      "/root/child",
			attribute: "asdasd",
			expected:  "",
		},
		{
			name:      "Non existing path for XMLGetAttributeValue",
			xmlString: `<root><child attr="value"/></root>`,
			path:      "/foo/bar",
			attribute: "asdasd",
			expected:  "",
		},
		{
			name:      "Invalid XML for XMLGetAttributeValue",
			xmlString: `<root><`,
			path:      "/foo/bar",
			attribute: "asdasd",
			expected:  "",
		},
		{
			name:      "Invalid path for XMLGetAttributeValue",
			xmlString: `<root><child attr="value"/></root>`,
			path:      "/foo/bar[@",
			attribute: "asdasd",
			expected:  "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := XMLGetAttributeValue(tc.xmlString, tc.path, tc.attribute)
			require.Equal(t, tc.expected, result)
		})
	}

}
func TestXMLGetNodeValue(t *testing.T) {
	err := Init(nil)
	require.NoError(t, err)

	tests := []struct {
		name      string
		xmlString string
		path      string
		expected  string
	}{
		{
			name:         "XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/root/child",
			expected: "foobar",
		},
		{
			name:         "Non existing path for XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/foo/bar",
			expected: "",
		},
		{
			name:         "Invalid XML for XMLGetNodeValue",
			xmlString:    `<root><`,
			path:         "/foo/bar",
			expected: "",
		},
		{
			name:         "Invalid path for XMLGetNodeValue",
			xmlString:    `<root><child>foobar</child></root>`,
			path:         "/foo/bar[@",
			expected: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := XMLGetNodeValue(tc.xmlString, tc.path)
			require.Equal(t, tc.expected, result)
		})
	}

}
