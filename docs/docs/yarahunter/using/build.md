---
title: Build YaraHunter
---

# Build YaraHunter

YaraHunter is a self-contained docker-based tool. Clone the [YaraHunter repository](https://github.com/deepfence/YaraHunter), then build:

```bash
docker build --rm=true --tag=deepfenceio/yara-hunter:latest -f Dockerfile .
```

Alternatively, you can pull the official deepfence image at `deepfenceio/yara-hunter:latest`.

```bash
docker pull deepfenceio/yara-hunter:latest
```
