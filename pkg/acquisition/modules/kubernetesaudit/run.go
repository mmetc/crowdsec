package kubernetesauditacquisition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apiserver/pkg/apis/audit"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	s.outChan = out

	s.logger.Infof("Starting k8s-audit server on %s:%d%s", s.config.ListenAddr, s.config.ListenPort, s.config.WebhookPath)

	serverErr := make(chan error, 1)

	go func() {
		err := s.server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("k8s-audit server failed: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Infof("Stopping k8s-audit server on %s:%d%s", s.config.ListenAddr, s.config.ListenPort, s.config.WebhookPath)

		if err := s.server.Shutdown(context.Background()); err != nil { //nolint:contextcheck // shutdown needs a fresh context after parent cancellation
			s.logger.Errorf("Error shutting down k8s-audit server: %s", err.Error())
		}

		return nil
	case err := <-serverErr:
		return err
	}
}

func (s *Source) webhookHandler(w http.ResponseWriter, r *http.Request) {
	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.K8SAuditDataSourceRequestCount.WithLabelValues(s.addr).Inc()
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.logger.Tracef("webhookHandler called")

	var auditEvents audit.EventList

	jsonBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Errorf("Error reading request body: %v", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	s.logger.Tracef("webhookHandler receveid: %s", string(jsonBody))

	err = json.Unmarshal(jsonBody, &auditEvents)
	if err != nil {
		s.logger.Errorf("Error decoding audit events: %s", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	remoteIP := strings.Split(r.RemoteAddr, ":")[0]

	for idx := range auditEvents.Items {
		if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.K8SAuditDataSourceEventCount.With(prometheus.Labels{"source": s.addr, "datasource_type": ModuleName, "acquis_type": s.config.Labels["type"]}).Inc()
		}

		bytesEvent, err := json.Marshal(auditEvents.Items[idx])
		if err != nil {
			s.logger.Errorf("Error serializing audit event: %s", err)
			continue
		}

		s.logger.Tracef("Got audit event: %s", string(bytesEvent))
		l := pipeline.Line{
			Raw:     string(bytesEvent),
			Labels:  s.config.Labels,
			Time:    auditEvents.Items[idx].StageTimestamp.Time,
			Src:     remoteIP,
			Process: true,
			Module:  s.GetName(),
		}

		evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
		evt.Line = l

		s.outChan <- evt
	}
}
