---
title: Using over GRPC
---

# Using over GRPC

You can run a persistent MalwareScanner service and issue requests for scans using GRPC.  You first need to build MalwareScanner from source, to generate the necessary proto files.

:::info

### Help needed!

These instructions are out-of-date and need refreshed
:::

## Prerequisites

You will need the [grcpurl](https://github.com/fullstorydev/grpcurl) tool.


## Run the MalwareScanner gRPC server

Start the MalwareScanner gRPC server:

```bash
docker run -it --rm --name=deepfence-malwarescanner \
	-v $(pwd):/home/deepfence/output \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v /tmp/sock:/tmp/sock \
	quay.io/deepfenceio/deepfence_malware_scanner_ce:2.3.1 \
	-socket-path /tmp/sock/s.sock
```


## Scan a Container Image

```bash
# run this from the repo directory, or update the import-path

grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto malware_scanner.proto \
    -d '{"image": {"name": "node:latest"}}' \
    -unix '/tmp/sock.sock' \
    malware_scanner.MalwareScanner/FindMalwareInfo
```

## Scan a Local Directory

```bash
# run this from the repo directory, or update the import-path

grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto malware_scanner.proto \
	-d '{"path": "/tmp"}' \
	-unix '/tmp/sock.sock' \
	malware_scanner.MalwareScanner/FindMalwareInfo
```

