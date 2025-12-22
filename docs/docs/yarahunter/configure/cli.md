---
title: Command-Line Options
---

# Command Line Options

Display the command line options:

```bash
$ docker run -it --rm quay.io/deepfenceio/deepfence_malware_scanner_ce:2.5.8 --help
```

Note that all files and directories used in YaraHunter configuration are local to the container, not the host filesystem. The examples given illustrate how to map host directories to the container when needed.

### General Configuration

 * `--debug-level string`: one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG (default "ERROR"); print messages of this severity or higher.
 * `--threads int`: Number of concurrent threads to use during scan (default number of logical CPUs).
 * `--temp-directory string`: temporary storage for working data (default "/tmp")

 * `--max-ioc uint`: Maximum number of indicator of compromise matches to report from a container image or file system (default 1000).
 * `--maximum-file-size int`: Maximum file size to process in bytes (default 32Mb, 33554432 bytes).

### Scan Containers

 * `--image-name string`: scan this image (name:tag) in the local registry
 * `--container-id string`: scan a running container, identified by the provided container ID
 * `--container-ns string`: search the provided namespace (not used for Docker runtime)

### Scan Filesystems

 * `--local string`: scan the local directory in the YaraHunter docker container.  Mount the external (host) directory within the container using `-v`
 * `--host-mount-path string`: inform YaraHunter of the location in the container where the host filesystem was mounted, such as '/tmp/mnt'. YaraHunter uses this as the root directory when matching `exclude_paths` such as `/var/lib` (see below) 

### Configure Output

YaraHunter can write output as Table and JSON format

 * `-output`: Output format: json or table (default "table")

### Configure Rules

YaraHunter applies YARA rules from the local container filesystem; all `*.yar` and `*.yara` files in the `rules-path` are considered. You can replace the default rules with your own by providing a different `rules-path`, mounted from the host filesystem.

 * `--fail-on-rule-compile-warn`: YaraHunter will fail if a yara rule compilation has warnings; otherwise, rules that fail to compile are just ignored
 * `--rules-path string`: all .yar and .yara files in the given local directory will be compiled (default "/home/deepfence/rules")
 
### Configure Scans

Scans can be fine-tuned using settings in `config.yaml`:

 * `--config-path string`: directory location of `config.yaml`. If not set, YaraHunter will fall back to the local binary directory or the current working directory.

`config.yaml` can be used to exclude files and locations from the malware scan:

```yaml
# YaraHunter Configuration File

exclude_strings: [] # skip matches containing any of these strings (case sensitive)
exclude_extensions: [ ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf", ".zip", ".tar.gz", ".ttf", ".lock", ".prerm"] 
# need to confirm as windows hides file extensions
exclude_paths: ["/var/lib/docker", "/var/lib/containerd", "/bin", "/boot", "/dev", "/lib", "/lib64", "/media", "/proc", "/run", "/sbin", "/usr/lib", "/sys"] # use \ for windows paths
```