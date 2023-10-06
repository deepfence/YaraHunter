---
title: Build YaraHunter
---

# Build YaraHunter

YaraHunter is a self-contained docker-based tool. Clone the [YaraHunter repository](https://github.com/deepfence/YaraHunter), then build:

```bash
docker build --rm=true --tag=deepfenceio/deepfence_malware_scanner_ce:2.0.0 -f Dockerfile .
```

Alternatively, you can pull the official deepfence image at `deepfenceio/deepfence_malware_scanner_ce:2.0.0`.

```bash
docker pull deepfenceio/deepfence_malware_scanner_ce:2.0.0
```
