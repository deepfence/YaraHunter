# IOCScanner



$ ./IOCScanner --help

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
docker pull node:8.11
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

* Or run IOCScanner as a gRPC server:
    ```shell
    docker run -it --rm --name=deepfence-ioc-scanner -v $(pwd):/home/deepfence/output -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/sock:/tmp/sock deepfenceio -socket-path /tmp/sock/s.sock
    ```
  * Scan a container image:
    ```shell
    grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto IOC_scanner.proto -d '{"image": {"name": "node:8.11"}}' -unix '/tmp/sock.sock' IOC_scanner.IOCScanner/FindIOCInfo
    ```

  * Scan a local directory:
    ```shell
    grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto IOC_scanner.proto -d '{"path": "/tmp"}' -unix '/tmp/sock.sock' IOC_scanner.IOCScanner/FindIOCInfo
    ```

By default, IOCScanner will also create json files with details of all the IOC found in the current working directory. You can explicitly specify the output directory and json filename using the appropriate options.

Please note that you can use `nerdctl` as an alternative to `docker` in the commands above.

## Build Instructions

1. Run boostrap.sh
2. Install Docker
3. Install Hyperscan
4. Install go for your platform (version 1.14)
5. Install go modules, if needed: `gohs`, `yaml.v3` and `color`
6. `go get github.com/deepfence/IOCScanner` will download and build IOCScanner automatically in `$GOPATH/bin` or `$HOME/go/bin` directory. Or, clone this repository and run `go build -v -i` to build the executable in the current directory.
7. Edit config.yaml file as needed and run the IOC scanner with the appropriate config file directory.

For reference, the [Install file](https://github.com/deepfence/IOCScanner/blob/master/Install.Ubuntu) has commands to build on an ubuntu system.

## Instructions to Run on Local Host

### As a standalone application

```shell
./IOCScanner --help

./IOCScanner -config-path /path/to/config.yaml/dir -local test

./IOCScanner -config-path /path/to/config.yaml/dir -image-name node:8.11
```

### As a server application
```shell
./IOCScanner -socket-path /path/to/socket.sock
```

See "Quickly-Try-Using-Docker" section above to see how to send requests.

## Sample IOCScanner Output

![SampleJsonOutput](images/SampleIOCsOutput.png)

# Credits

We have built upon the configuration file from [shhgit](https://github.com/eth0izzle/shhgit) project.

# Disclaimer

This tool is not meant to be used for hacking. Please use it only for legitimate purposes like detecting IOC on the infrastructure you own, not on others' infrastructure. DEEPFENCE shall not be liable for loss of profit, loss of business, other financial loss, or any other loss or damage which may be caused, directly or indirectly, by the inadequacy of IOCScanner for any purpose or use thereof or by any defect or deficiency therein.
