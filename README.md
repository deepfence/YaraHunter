# IOCScanner

```
$ docker run -it --rm deepfenceio/deepfence-ioc-scanner:latest --help

Usage of ./IOCScanner:
  -config-path string
    	Searches for config.yaml from given directory. If not set, tries to find it from IOCScanner binary's and current directory
  -debug-level string
    	Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed (default "ERROR")
  -image-name string
    	Name of the image along with tag to scan for IOC
  -json-filename string
    	Output json file name. If not set, it will automatically create a filename based on image or dir name
  -local string
    	Specify local directory (absolute path) which to scan. Scans only given directory recursively.
  -max-multi-match uint
    	Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled. (default 3)
  -max-ioc uint
    	Maximum number of IOC to find in one container image or file system. (default 1000)
  -maximum-file-size uint
    	Maximum file size to process in KB (default 256)
  -multi-match
    	Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance
  -output-path string
    	Output directory where json file will be stored. If not set, it will output to current directory
  -temp-directory string
    	Directory to process and store repositories/matches (default "/tmp")
  -threads int
    	Number of concurrent threads (default number of logical CPUs)
  -socket-path string
  		The gRPC server socket path
```

## Quickly Try Using Docker

Install docker and run IOCScanner on a container image using the following instructions:

* Build IOCScanner:
```shell
./bootstrap.sh
docker build --rm=true --tag=deepfenceio/deepfence-ioc-scanner:latest -f Dockerfile .
```

* Or, pull the latest build from docker hub by doing:
```shell
docker pull deepfenceio/deepfence-ioc-scanner:latest
```

* Pull a container image for scanning:
```shell
docker pull node:10.19
```

* Run IOCScanner as a standalone:
  * Scan a container image:
    ```shell
    docker run -it --rm --name=deepfence-ioc-scanner -v $(pwd):/home/deepfence/output -v /var/run/docker.sock:/var/run/docker.sock deepfenceio/deepfence-ioc-scanner:latest -image-name node:10.19
    ```

  * Scan a local directory:
    ```shell
    docker run -it --rm --name=deepfence-ioc-scanner -v /:/deepfence/mnt -v $(pwd):/home/deepfence/output -v /var/run/docker.sock:/var/run/docker.sock deepfenceio/deepfence-ioc-scanner:latest -host-mount-path /deepfence/mnt -local /deepfence/mnt
    ```

By default, IOCScanner will also create json files with details of all the IOC found in the current working directory. You can explicitly specify the output directory and json filename using the appropriate options.

## Sample IOCScanner Output

![SampleJsonOutput](images/SampleIOCsOutput.png)

# Disclaimer

This tool is not meant to be used for hacking. Please use it only for legitimate purposes like detecting IOC on the infrastructure you own, not on others' infrastructure. DEEPFENCE shall not be liable for loss of profit, loss of business, other financial loss, or any other loss or damage which may be caused, directly or indirectly, by the inadequacy of IOCScanner for any purpose or use thereof or by any defect or deficiency therein.
