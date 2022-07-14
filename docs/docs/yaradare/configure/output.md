---
title: Output
---


# Configure Output

YaRadare can write its JSON output to a container-local file (`--json-file`).

By default, the output is written to `/home/deepfence/output` in the container filesystem.  You can mount a host directory over this location.

```bash
# Write output to ./my-output/node-scan.json

mkdir ./my-output

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
# highlight-next-line
    -v $(pwd)/my-output:/home/deepfence/output \
    deepfenceio/deepfence-yaradare:latest --image-name node:latest \
# highlight-next-line
    --json-file node-scan.json
```

You can also override the default output location (`--output-path`) in the container.