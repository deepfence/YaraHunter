---
title: YaraHunter QuickStart
---

# Quick Start

Pull the latest YaraHunter image, and use it to scan a `node:latest` container.

## Pull the latest YaraHunter image

```bash
docker pull deepfenceio/yara-hunter:latest
```

## Scan a Container Image

Pull an image to your local repository, then scan it

```bash
docker pull node:latest

docker run -it --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/yara-hunter:latest \
    --image-name node:latest

docker rmi node:latest
```

## Process the results with jq

You can summarise the results by processing the JSON output, e.g. using `jq`:

```bash
docker run -it --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp:/home/deepfence/output \
    deepfenceio/yara-hunter:latest \
    --image-name node:latest --json-filename=node-scan.json

cat /tmp/node-scan.json | jq '.IOC[] | ."Matched Rule Name"'
```