package main

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

const accessLogFilename = "crowdsec_api.log"

func initAPIServer(ctx context.Context, cConfig *csconfig.Config) (*apiserver.APIServer, error) {
	if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
		log.Info("push and pull to Central API disabled")
	}

	if cConfig.API.Server.ListenURI != "" {
		listenConfig := &net.ListenConfig{}
		listener, err := listenConfig.Listen(ctx, "tcp", cConfig.API.Server.ListenURI)
		if err != nil {
			return nil, fmt.Errorf("local API server stopped with error: listening on %s: %w", cConfig.API.Server.ListenURI, err)
		}
		_ = listener.Close()
	}

	accessLogger := cConfig.API.Server.NewAccessLogger(cConfig.Common.LogConfig, accessLogFilename)

	apiServer, err := apiserver.NewServer(ctx, cConfig.API.Server, accessLogger)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	err = apiServer.InitPlugins(ctx, cConfig, &pluginBroker)
	if err != nil {
		return nil, err
	}

	err = apiServer.InitController()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %w", err)
	}

	return apiServer, nil
}

func serveAPIServer(ctx context.Context, apiServer *apiserver.APIServer) {
	apiReady := make(chan bool, 1)
	runCtx, cancel := context.WithCancel(ctx)
	apiCancel = cancel
	apiDone = make(chan error, 1)

	go func() {
		defer trace.ReportPanic()

		pluginCtx, cancelPlugin := context.WithCancel(runCtx)
		pluginDone := make(chan struct{})

		go func() {
			defer trace.ReportPanic()
			defer close(pluginDone)
			pluginBroker.Run(pluginCtx)
		}()

		runErr := make(chan error, 1)

		go func() {
			defer trace.ReportPanic()

			log.Debugf("serving API after %s ms", time.Since(crowdsecT0))

			runErr <- apiServer.Run(runCtx, apiReady)
		}()

		select {
		case err := <-runErr:
			if err != nil && runCtx.Err() == nil {
				log.Fatal(err)
			}
			cancelPlugin()
			<-pluginDone
			apiDone <- err
		case <-runCtx.Done():
			log.Infof("serve: shutting down api server")

			shutdownCtx, cancelShutdown := context.WithTimeout(context.WithoutCancel(runCtx), 5*time.Second)
			err := apiServer.Shutdown(shutdownCtx)
			cancelShutdown()

			if runErrValue := <-runErr; runErrValue != nil && err == nil {
				err = runErrValue
			}

			cancelPlugin()
			<-pluginDone
			apiDone <- err
		}
	}()

	select {
	case <-apiReady:
	case err := <-apiDone:
		if err != nil {
			log.Fatal(err)
		}
	}
}
