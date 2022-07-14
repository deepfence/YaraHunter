---
title: Command-Line Options
---


## Command Line Options

Display the command line options:

```bash
$ docker run -it --rm deepfenceio/deepfence-yaradare:latest --help
```

Note that all files and directories used in YaRadare configuration are local to the container, not the host filesystem. The examples above illustrate how to map host directories to the container when needed.

### General Configuration

 * `--log-level string`: one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG (default "ERROR"); print messages of this severity or higher.
 * `--threads int`: Number of concurrent threads to use during scan (default number of logical CPUs).
 * `--temp-directory string`: temporary storage for working data (default "/tmp")

 * `--max-ioc uint`: Maximum number of indicator of compromise matches to report from a container image or file system (default 1000).
 * `--maximum-file-size int`: Maximum file size to process in bytes (default 32Mb, 33554432 bytes).

### Scan Containers

 * `--image-name string`: scan this image (name:tag) in the local registry
 * `--container-id string`: scan a running container, identified by the provided container ID
 * `--container-ns string`: search the provided namespace (not used for Docker runtime)

### Scan Filesystems

 * `--local string`: scan the local directory in the YaRadare docker container.  Mount the external (host) directory within the container using `-v`
 * `--host-mount-path string`: inform YaRadare of the location in the container where the host filesystem was mounted, such as '/tmp/mnt'. YaRadare uses this as the root directory when matching `exclude_paths` such as `/var/lib` (see below) 

### Configure Output

In addition to writing output to **stdout** / **stderr**, YaRadare can write JSON output to a local file. You may wish to mount a directory on the host into `output-path` in the container so that you can easily obtain the JSON output file.

 * `--json-filename string`: output json file name; required
 * `--output-path string`: location in container where json file will be stored (default `/home/deepfence/output`)

### Configure Rules

YaRadare applies YARA rules from the local container filesystem; all `*.yar` and `*.yara` files in the `rules-path` are considered. You can replace the default rules with your own by providing a different `rules-path`, mounted from the host filesystem.

 * `--fail-on-rule-compile-warn`: YaRadare will fail if a yara rule compilation has warnings; otherwise, rules that fail to compile are just ignored
 * `--rules-path string`: all .yar and .yara files in the given local directory will be compiled (default "/home/deepfence/rules")
 
### Configure Scans

Scans can be fine-tuned using settings in `config.yaml`:

 * `--config-path string`: directory location of `config.yaml`. If not set, YaRadare will fall back to the local binary directory or the current working directory.

`config.yaml` can be used to exclude files and locations from the malware scan:

```yaml
# YaRadare Configuration File

exclude_strings: [] # skip matches containing any of these strings (case sensitive)
exclude_extensions: [ ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf", ".zip", ".tar.gz", ".ttf", ".lock"] 
# need to confirm as windows hides file extensions
exclude_paths: ["/var/lib/docker", "/var/lib/containerd", "/bin", "/boot", "/dev", "/lib", "/lib64", "/media", "/proc", "/run", "/sbin", "/usr/lib", "/sys"] # use \ for windows paths
```