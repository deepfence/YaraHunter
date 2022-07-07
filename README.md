[![GitHub license](https://img.shields.io/github/license/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)


# YaRadare

Deepfence YaRadare ("Ya-Radar") scans container images, running Docker containers, and filesystems to find indicators of malware. It uses a [YARA ruleset](https://virustotal.github.io/yara/) to identify resources that match known malware signatures, and may indicate that the container or filesystem has been compromised.

YaRadare can be used in the following ways:

 * At build time: scan images during the CI/CD pipeline, to determine if they are subject to a supply-chain compromise
 * At rest: scan local container images, for example, before they are deployed, to verify they do not contain malware
 * At runtime: scan running docker containers, for example, if you observe unusual network traffic or CPU activity
 * Against filesystems: at any time, YaRadare can scan a local filesystems for indicators of compromise

Key capabilities:

 * Scan running and at-rest containers, and filesystems
 * Run anywhere: highly-portable, docker container form factor or universal GO binary
 * Designed for automation: easy-to-deploy, easy-to-parse JSON output

YaRadare is a work-in-progress (check the [Roadmap](https://github.com/orgs/deepfence/projects/3) and [issues list](issues)), and will be integrated into the [ThreatMapper](/deepfence/ThreatMapper) threat discovery platform.  We welcome any contributions to help to improve this tool.

## Getting Started

### Build YaRadare

YaRadare is a self-contained docker-based tool. Clone this repository, then build:

```
docker build --rm=true --tag=deepfenceio/deepfence-yaradare:latest -f Dockerfile .
```

Alternatively, you can pull the ‘official’ deepfence image at `deepfenceio/deepfence-yaradare:latest`.

### Scan a Container Image

Pull the image to your local repository, then scan it

<pre><code>docker pull node:latest

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/deepfence-yaradare:latest <b>--image-name node:latest</b>

docker rmi node:latest
</code></pre>

### Scan a Running Container

<pre><code>docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    <b>-v /:/deepfence/mnt</b> \
    deepfenceio/deepfence-yaradare:latest <b>--host-mount-path /deepfence/mnt --container-id 69221b948a73</b>
</code></pre>

### Scan a filesystem

Mount the filesystem within the YaRadare container and scan it:

<pre><code>docker run -it --rm --name=deepfence-yaradare \
    <b>-v ~/src/YARA-RULES:/tmp/YARA-RULES</b> \
    deepfenceio/deepfence-yaradare:latest <b>--local /tmp/YARA-RULES</b>
</code></pre>

## Example:

TODO: find an example that illustrates the malware detection capabilities, illustrate it inline


## Command Line Options

Display the command line options:

<pre><code>$ docker run -it --rm deepfenceio/deepfence-yaradare:latest <b>--help</b></code></pre>

 * `--config-path string`: searches for `config.yaml` from given directory. If not set, fall back to the YaRadare binary directory and the current working directory.
 * `--max-ioc uint`: Maximum number of indicator of compromise matches to report from a container image or file system (default 1000).
 * `--maximum-file-size int`:	Maximum file size to process in bytes (default 32Mb).
 * `--threads int`:	Number of concurrent threads to use during scan (default number of logical CPUs).
 * `--log-level string`: one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG (default "ERROR"); print messages of this severity or higher.
 * `--temp-directory string`: temporary storage for working data (default "/tmp")

#### Scan Containers

 * `--image-name string`: scan this image (name:tag) in the local registry
 * `--container-id string`: scan a running container, identified by the provided container ID
 * `--container-ns string`: search the provided namespace (not used for Docker runtime)

#### Scan Filesystems

 * `--local string`: scan the local directory in the YaRadare docker container.  Mount the external (host) directory within the container using `-v`
 * `--host-mount-path string`: If scanning the host, specify the host mount path for path exclusions to work correctly.  **TODO: clarify the meaning**

#### Configure Output

 * `--json-filename string`: Output json file name. If not set, it will automatically create a filename based on image or dir name. **TODO: not implemented?**
 * `--output-path string`: Output directory where json file will be stored (default "."). **TODO: not implemented?**

### Detailed Configuration

YaRadare's scanning operation can be fine-tuned using `config.yaml`, to exclude files and locations from the malware scan:

```
# YaRadare Configuration File

exclude_strings: [] # skip matches containing any of these strings (case sensitive)
exclude_extensions: [ ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf", ".zip", ".tar.gz", ".ttf", ".lock"] 
# need to confirm as windows hides file extensions
exclude_paths: ["/var/lib/docker", "/var/lib/containerd", "/bin", "/boot", "/dev", "/lib", "/lib64", "/media", "/proc", "/run", "/sbin", "/usr/lib", "/sys"] # use \ for windows paths
```

YaRadare reads `config.yaml` from the location of the YaRadare binary or from the current working directory; the location can be overriden using the `--config-path` command line argument.


# Disclaimer

This tool is not meant to be used for hacking. Please use it only for legitimate purposes like detecting indicator of compromise on the infrastructure you own, not on others' infrastructure. DEEPFENCE shall not be liable for loss of profit, loss of business, other financial loss, or any other loss or damage which may be caused, directly or indirectly, by the inadequacy of YaRadare for any purpose or use thereof or by any defect or deficiency therein.
