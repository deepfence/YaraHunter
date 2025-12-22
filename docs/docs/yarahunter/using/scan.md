---
title: Scan with YaraHunter
---


# Scanning with YaraHunter

You can use YaraHunter to scan running or at-rest container images, and local file systems.  YaraHunter will match the assets it finds against the YARA rules it has been configured with.

## Scan a Container Image

Pull the image to your local repository, then scan it

```bash
docker pull node:latest

docker run -it --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.8 \
# highlight-next-line
    --image-name node:latest

docker rmi node:latest
```

### Scan a Running Container

Mount the root directory into the YaraHunter container at a location of your choosing (e.g. `/deepfence/mnt`) and specify the running container ID:

```bash
docker run -it --rm --name=yara-hunter \
    -v /var/run/docker.sock:/var/run/docker.sock \
# highlight-next-line
    -v /:/deepfence/mnt \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.8 \
# highlight-next-line
    --host-mount-path /deepfence/mnt --container-id 69221b948a73
```

### Scan a filesystem

Mount the filesystem within the YaraHunter container and scan it:

```bash
docker run -it --rm --name=yara-hunter \
# highlight-next-line
    -v ~/src/YARA-RULES:/tmp/YARA-RULES \
    quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.8 \
# highlight-next-line
    --local /tmp/YARA-RULES --host-mount-path /tmp/YARA-RULES
```

### Scan during CI/CD build

Refer to the detailed [documentation for CI/CD integration](https://github.com/deepfence/YaraHunter/tree/main/ci-cd-integration).
