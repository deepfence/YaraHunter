---
title: Introduction to YaraHunter
---

# YaraHunter

Deepfence YaraHunter scans container images, running Docker containers, and filesystems to find indicators of malware. It uses a [YARA ruleset](https://github.com/deepfence/yara-rules) to identify resources that match known malware signatures, and may indicate that the container or filesystem has been compromised.


Key capabilities:

 * Scan running and at-rest containers; scan filesystems; scan during CI/CD build operations
 * Run anywhere: highly-portable, docker container form factor
 * Designed for automation: easy-to-deploy, easy-to-parse JSON output


## YaraHunter in Action

![Yadare in Action](img/yarahunter.svg)


## Example: Finding Indicators of Compromise in a Container Image

Images may be compromised with the installation of a cryptominer such as XMRig.  In the following example, we'll scan a legitimiate cryptominer image that contains the same xmrig software that is often installed through an exploit:

```bash
docker pull metal3d/xmrig

docker run -i --rm --name=deepfence-yarahunter \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /tmp:/home/deepfence/output \
     quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0 \
     --image-name metal3d/xmrig:latest \
     --output=json > xmrig-scan.json
```

This returns, among other things, clear indication of the presence of XMRig.  Note that we store the output (`/tmp/xmrig-scan.json`) for quick and easy manipulation:

```bash
# Extract the IOC array values.  From these, extract the values of the 'Matched Rule Name' key
cat /tmp/xmrig-scan.json | jq '.IOC[] | ."Matched Rule Name"'
```

This returns a list of the IOCs identified in the container we scanned.

## When to use YaraHunter

YaraHunter can be used in the following ways:

 * **At build-and-test**: scan build artifacts in the CI/CD pipeline, reporting on possible indicators of malware
 * **At rest**: scan local container images, for example, before they are deployed, to verify they do not contain malware
 * **At runtime**: scan running docker containers, for example, if you observe unusual network traffic or CPU activity
 * **Against filesystems**: at any time, YaraHunter can scan a local filesystems for indicators of compromise