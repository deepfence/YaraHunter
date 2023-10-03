---
title: Configure Output
---


# Configure Output

YaraHunter can writes output to `stdout` it can redirected to a file for further analysis.

```bash
docker run -i --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/yara-hunter:latest \
    --image-name node:latest \
# highlight-next-line
    --output=json > xmrig-scan.json
```
