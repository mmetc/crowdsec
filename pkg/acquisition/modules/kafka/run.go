package kafkaacquisition

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/segmentio/kafka-go"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (s *Source) ReadMessage(ctx context.Context, out chan pipeline.Event) error {
	if s.Config.GroupID == "" {
		err := s.Reader.SetOffset(kafka.LastOffset)
		if err != nil {
			return fmt.Errorf("while setting offset for reader on topic '%s': %w", s.Config.Topic, err)
		}
	}

	for {
		s.logger.Tracef("reading message from topic '%s'", s.Config.Topic)

		m, err := s.Reader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}

			s.logger.Errorln(fmt.Errorf("while reading %s message: %w", s.GetName(), err))

			continue
		}

		s.logger.Tracef("got message: %s", string(m.Value))
		l := pipeline.Line{
			Raw:     string(m.Value),
			Labels:  s.Config.Labels,
			Time:    m.Time.UTC(),
			Src:     s.Config.Topic,
			Process: true,
			Module:  s.GetName(),
		}
		s.logger.Tracef("line with message read from topic '%s': %+v", s.Config.Topic, l)

		if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.KafkaDataSourceLinesRead.With(prometheus.Labels{"topic": s.Config.Topic, "datasource_type": ModuleName, "acquis_type": l.Labels["type"]}).Inc()
		}

		evt := pipeline.MakeEvent(s.Config.UseTimeMachine, pipeline.LOG, true)
		evt.Line = l

		out <- evt
	}
}

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	s.logger.Infof("start reader on brokers '%+v' with topic '%s'", s.Config.Brokers, s.Config.Topic)

	defer func() {
		s.logger.Infof("%s datasource topic %s stopping", s.GetName(), s.Config.Topic)

		if err := s.Reader.Close(); err != nil {
			s.logger.Errorf("while closing %s reader on topic '%s': %s", s.GetName(), s.Config.Topic, err)
		}
	}()

	return s.ReadMessage(ctx, out)
}
