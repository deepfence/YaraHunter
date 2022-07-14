---
title: Build YaRadare
---

# Build YaRadare

YaRadare is a self-contained docker-based tool. Clone this repository, then build:

```bash
docker build --rm=true --tag=deepfenceio/deepfence-yaradare:latest -f Dockerfile .
```

Alternatively, you can pull the ‘official’ deepfence image at `deepfenceio/deepfence-yaradare:latest`.
