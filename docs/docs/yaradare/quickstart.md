---
title: YaRadare QuickStart
---

# Quick Start

Pull the latest YaRadare image, and use it to scan a `node:latest` container.

## Pull the latest YaRadare image

```bash
docker pull deepfenceio/deepfence-yaradare:latest
```

## Scan a Container Image

Pull an image to your local repository, then scan it

```bash
docker pull node:latest

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/deepfence-yaradare:latest \
    --image-name node:latest

docker rmi node:latest
```

## Process the results with jq

You can summarise the results by processing the JSON output, e.g. using `jq`:

```bash
docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp:/home/deepfence/output \
    deepfenceio/deepfence-yaradare:latest \
    --image-name node:latest --json-filename=node-scan.json

cat /tmp/node-scan.json | jq '.IOC[] | ."Matched Rule Name"'
```