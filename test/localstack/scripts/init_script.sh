#!/bin/bash

#apt install netcat-openbsd -y
#
## Wait for LocalStack to be ready
#while ! nc -z localstack 4566; do
#  sleep 1
#done

# Create Kinesis streams
aws --endpoint-url=http://localstack:4566 --region us-east-1 kinesis create-stream --stream-name stream-1-shard --shard-count 1
aws --endpoint-url=http://localstack:4566 --region us-east-1 kinesis create-stream --stream-name stream-2-shards --shard-count 2

