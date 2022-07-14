---
title: Scan with YaRadare
---


# Scanning with YaRadare

You can use YaRadare to scan running or at-rest container images, and local file systems.  YaRadare will match the assets it finds against the YARA rules it has been configured with.

## Scan a Container Image

Pull the image to your local repository, then scan it

```bash
docker pull node:latest

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/deepfence-yaradare:latest \
# highlight-next-line
    --image-name node:latest

docker rmi node:latest
```

### Scan a Running Container

Mount the root directory into the YaRadare container at a location of your choosing (e.g. `/deepfence/mnt`) and specify the running container ID:

```bash
docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
# highlight-next-line
    -v /:/deepfence/mnt \
    deepfenceio/deepfence-yaradare:latest \
# highlight-next-line
    --host-mount-path /deepfence/mnt --container-id 69221b948a73
```

### Scan a filesystem

Mount the filesystem within the YaRadare container and scan it:

```bash
docker run -it --rm --name=deepfence-yaradare \
# highlight-next-line
    -v ~/src/YARA-RULES:/tmp/YARA-RULES \
    deepfenceio/deepfence-yaradare:latest \
# highlight-next-line
    --local /tmp/YARA-RULES --host-mount-path /tmp/YARA-RULES
```

### Scan during CI/CD build

Refer to the detailed [documentation for CI/CD integration](https://github.com/deepfence/YaRadare/tree/main/ci-cd-integration).
