---
title: Configure Output
---


# Configure Output

YaraHunter can writes output to `stdout`. It can be redirected to a file for further analysis.

```bash
docker run -i --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.8 \
    --image-name node:latest \
# highlight-next-line
    --output=json > xmrig-scan.json
```
