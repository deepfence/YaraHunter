---
title: YaraHunter QuickStart
---

# Quick Start

Pull the latest YaraHunter image, and use it to scan a `node:latest` container.

## Pull the latest YaraHunter image

```bash
docker pull quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0
```

## Scan a Container Image

Pull an image to your local repository, then scan it

```bash
docker pull node:latest

docker run -i --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0 \
    --image-name node:latest

docker rmi node:latest
```

## Process the results with jq

You can summarise the results by processing the JSON output, e.g. using `jq`:

```bash
docker run -i --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp:/home/deepfence/output \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0 \
    --image-name node:latest \
    --output=json > node-latest.json

cat /tmp/node-latest.json | jq '.IOC[] | ."Matched Rule Name"'
```