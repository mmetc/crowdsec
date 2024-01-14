package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrepareApiURL_NoProtocol(t *testing.T) {

	url, err := prepareApiURL(nil, "localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())

}

func TestPrepareApiURL_Http(t *testing.T) {

	url, err := prepareApiURL(nil, "http://localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:81/", url.String())

}

func TestPrepareApiURL_Https(t *testing.T) {

	url, err := prepareApiURL(nil, "https://localhost:81")
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:81/", url.String())

}

func TestPrepareApiURL_UnixSocket(t *testing.T) {

	url, err := prepareApiURL(nil, "/path/socket")
	assert.NoError(t, err)
	assert.Equal(t, "/path/socket/", url.String())

}

func TestPrepareApiURL_Empty(t *testing.T) {

	_, err := prepareApiURL(nil, "")
	assert.Error(t, err)

}

func TestPrepareApiURL_Empty_ConfigOverride(t *testing.T) {

	url, err := prepareApiURL(&csconfig.LocalApiClientCfg{
		Credentials: &csconfig.ApiCredentialsCfg{
			URL: "localhost:80",
		},
	}, "")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:80/", url.String())

}
