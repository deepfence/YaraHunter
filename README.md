[![GitHub license](https://img.shields.io/github/license/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/YaRadare)](https://github.com/deepfence/YaRadare/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)


# YaRadare

Deepfence YaRadare ("Yara-rā,där") scans container images, running Docker containers, and filesystems to find indicators of malware. It uses a [YARA ruleset](https://github.com/deepfence/yara-rules) to identify resources that match known malware signatures, and may indicate that the container or filesystem has been compromised.

YaRadare can be used in the following ways:

 * **At build-and-test**: scan build artifacts in the CI/CD pipeline, reporting on possible indicators of malware
 * **At rest**: scan local container images, for example, before they are deployed, to verify they do not contain malware
 * **At runtime**: scan running docker containers, for example, if you observe unusual network traffic or CPU activity
 * **Against filesystems**: at any time, YaRadare can scan a local filesystems for indicators of compromise

Key capabilities:

 * Scan running and at-rest containers; scan filesystems; scan during CI/CD build operations
 * Run anywhere: highly-portable, docker container form factor
 * Designed for automation: easy-to-deploy, easy-to-parse JSON output

YaRadare is a work-in-progress (check the [Roadmap](https://github.com/orgs/deepfence/projects/3) and [issues list](issues)), and will be integrated into the [ThreatMapper](/deepfence/ThreatMapper) threat discovery platform.  We welcome any contributions to help to improve this tool.

## Getting Started

### YaRadare in action

![demo gif](demo.gif)

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
    deepfenceio/deepfence-yaradare:latest \
    <b>--host-mount-path /deepfence/mnt --container-id 69221b948a73</b>
</code></pre>

### Scan a filesystem

Mount the filesystem within the YaRadare container and scan it:

<pre><code>docker run -it --rm --name=deepfence-yaradare \
    <b>-v ~/src/YARA-RULES:/tmp/YARA-RULES</b> \
    deepfenceio/deepfence-yaradare:latest \
    <b>--local /tmp/YARA-RULES --host-mount-path /tmp/YARA-RULES</b>
</code></pre>

### Scan during CI/CD build

Refer to the detailed [documentation for CI/CD integration](https://github.com/deepfence/YaRadare/tree/main/ci-cd-integration).

### Configure Output

YaRadare can write its JSON output to a container-local file (`--json-file`), which is written to `/home/deepfence/output` in the container filesystem by default: 

<pre><code>mkdir ./my-output

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    <b>-v $(pwd)/my-output:/home/deepfence/output</b> \
    deepfenceio/deepfence-yaradare:latest --image-name node:latest \
    <b>--json-file node-scan.json</b>
</code></pre>

You can also override the default output location (`--output-path`) in the container.

### Provide Custom Rules

YaRadare uses the YARA rules files (`*.yar` and `*.yara`) in the `/home/deepfence/rules` directory in the container.  You can provide an alternative set of rules, either at build-time, or by mounting a new rules directory into the container.

You can mount the rules directory over the existing one (`-v $(pwd)/my-rules:/home/deepfence/rules`), or you can mount it in a different location and specify it with `--rules-path`:

<pre><code>mkdir ./my-rules

# add your rules files (*.yar, *.yara) to my-rules

docker run -it --rm --name=deepfence-yaradare \
    -v /var/run/docker.sock:/var/run/docker.sock \
    <b>-v $(pwd)/my-rules:/tmp/my-rules</b> \
    deepfenceio/deepfence-yaradare:latest --image-name node:latest \
    <b>--rules-path /tmp/my-rules</b>
</code></pre>


## Example: finding Indicators of Compromise in a container image

Images may be compromised with the installation of a cryptominer such as XMRig.  In the following example, we'll scan a legitimiate cryptominer image that contains the same xmrig software that is often installed through an exploit:

```
docker pull metal3d/xmrig

docker run -it --rm --name=deepfence-yaradare \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /tmp:/home/deepfence/output \
     deepfenceio/deepfence-yaradare:latest --image-name metal3d/xmrig:latest \
     --json-filename=xmrig-scan.json
```

This returns, among other things, clear indication of the presence of XMRig.  Note that we store the output (`/tmp/xmrig-scan.json`) for quick and easy manipulation:

```
# Extract the IOC array values.  From these, extract the values of the 'Matched Rule Name' key
cat /tmp/xmrig-scan.json | jq '.IOC[] | ."Matched Rule Name"'
```

This returns a list of the IOCs identified in the container we scanned.


## Command Line Options

Display the command line options:

<pre><code>$ docker run -it --rm deepfenceio/deepfence-yaradare:latest <b>--help</b></code></pre>

Note that all files and directories used in YaRadare configuration are local to the container, not the host filesystem. The examples above illustrate how to map host directories to the container when needed.

#### General Configuration

 * `--log-level string`: one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG (default "ERROR"); print messages of this severity or higher.
 * `--threads int`:	Number of concurrent threads to use during scan (default number of logical CPUs).
 * `--temp-directory string`: temporary storage for working data (default "/tmp")

 * `--max-ioc uint`: Maximum number of indicator of compromise matches to report from a container image or file system (default 1000).
 * `--maximum-file-size int`:	Maximum file size to process in bytes (default 32Mb, 33554432 bytes).

#### Scan Containers

 * `--image-name string`: scan this image (name:tag) in the local registry
 * `--container-id string`: scan a running container, identified by the provided container ID
 * `--container-ns string`: search the provided namespace (not used for Docker runtime)

#### Scan Filesystems

 * `--local string`: scan the local directory in the YaRadare docker container.  Mount the external (host) directory within the container using `-v`
 * `--host-mount-path string`: inform YaRadare of the location in the container where the host filesystem was mounted, such as '/tmp/mnt'. YaRadare uses this as the root directory when matching `exclude_paths` such as `/var/lib` (see below) 

#### Configure Output

In addition to writing output to **stdout** / **stderr**, YaRadare can write JSON output to a local file. You may wish to mount a directory on the host into `output-path` in the container so that you can easily obtain the JSON output file.

 * `--json-filename string`: output json file name; required
 * `--output-path string`: location in container where json file will be stored (default `/home/deepfence/output`)

#### Configure Rules

YaRadare applies YARA rules from the local container filesystem; all `*.yar` and `*.yara` files in the `rules-path` are considered. You can replace the default rules with your own by providing a different `rules-path`, mounted from the host filesystem.

 * `--fail-on-rule-compile-warn`: YaRadare will fail if a yara rule compilation has warnings; otherwise, rules that fail to compile are just ignored
 * `--rules-path string`: all .yar and .yara files in the given local directory will be compiled (default "/home/deepfence/rules")
 
#### Configure Scans

Scans can be fine-tuned using settings in `config.yaml`:

 * `--config-path string`: directory location of `config.yaml`. If not set, YaRadare will fall back to the local binary directory or the current working directory.

`config.yaml` can be used to exclude files and locations from the malware scan:

```
# YaRadare Configuration File

exclude_strings: [] # skip matches containing any of these strings (case sensitive)
exclude_extensions: [ ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf", ".zip", ".tar.gz", ".ttf", ".lock"] 
# need to confirm as windows hides file extensions
exclude_paths: ["/var/lib/docker", "/var/lib/containerd", "/bin", "/boot", "/dev", "/lib", "/lib64", "/media", "/proc", "/run", "/sbin", "/usr/lib", "/sys"] # use \ for windows paths
```


# Disclaimer

This tool is not meant to be used for hacking. Please use it only for legitimate purposes like detecting indicator of compromise on the infrastructure you own, not on others' infrastructure. DEEPFENCE shall not be liable for loss of profit, loss of business, other financial loss, or any other loss or damage which may be caused, directly or indirectly, by the inadequacy of YaRadare for any purpose or use thereof or by any defect or deficiency therein.
