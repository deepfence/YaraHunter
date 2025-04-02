---
title: Configure Output
---


# Configure Output

YaraHunter can writes output to `stdout`. It can be redirected to a file for further analysis.

```bash
docker run -i --rm --name=yara-hunter \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.2 \
    --image-name node:latest \
# highlight-next-line
    --output=json > xmrig-scan.json
```
