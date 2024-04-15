---
title: Build YaraHunter
---

# Build YaraHunter

YaraHunter is a self-contained docker-based tool. Clone the [YaraHunter repository](https://github.com/deepfence/YaraHunter), then build:

```bash
docker build --rm=true --tag=quay.io/deepfenceio/deepfence_malware_scanner_ce:2.2.0 -f Dockerfile .
```

Alternatively, you can pull the official deepfence image at `quay.io/deepfenceio/deepfence_malware_scanner_ce:2.2.0`.

```bash
docker pull quay.io/deepfenceio/deepfence_malware_scanner_ce:2.2.0
```
