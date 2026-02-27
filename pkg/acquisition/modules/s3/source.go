package s3acquisition

import (
	"context"

	s3Manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type S3API interface {
	s3Manager.ListObjectsV2APIClient
	s3Manager.DownloadAPIClient
}

type SQSAPI interface {
	ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, params *sqs.DeleteMessageInput, optFns ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type Source struct {
	metricsLevel metrics.AcquisitionMetricsLevel
	Config       Configuration
	logger       *log.Entry
	s3Client     S3API
	sqsClient    SQSAPI
}

type S3Object struct {
	Key    string
	Bucket string
}

func (s *Source) GetMode() string {
	return s.Config.Mode
}

func (*Source) GetName() string {
	return ModuleName
}

func (s *Source) GetUuid() string {
	return s.Config.UniqueId
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
