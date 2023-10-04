package scan

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/deepfence/YaraHunter/core"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/vessel"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	podmanRuntime "github.com/deepfence/vessel/podman"
	vesselConstants "github.com/deepfence/vessel/utils"
	log "github.com/sirupsen/logrus"
)

type ContainerScan struct {
	containerId string
	tempDir     string
	namespace   string
	numIOC      uint
}

// Function to retrieve contents of container
// @parameters
// containerScan - Structure with details of the container to scan
// @returns
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) extractFileSystem() error {
	// Auto-detect underlying container runtime
	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		return err
	}
	var containerRuntimeInterface vessel.Runtime
	switch containerRuntime {
	case vesselConstants.DOCKER:
		containerRuntimeInterface = dockerRuntime.New(endpoint)
	case vesselConstants.CONTAINERD:
		containerRuntimeInterface = containerdRuntime.New(endpoint)
	case vesselConstants.CRIO:
		containerRuntimeInterface = crioRuntime.New(endpoint)
	case vesselConstants.PODMAN:
		containerRuntimeInterface = podmanRuntime.New(endpoint)
	}
	if containerRuntimeInterface == nil {
		return errors.New("could not detect container runtime")
	}
	err = containerRuntimeInterface.ExtractFileSystemContainer(containerScan.containerId, containerScan.namespace, containerScan.tempDir+".tar")

	if err != nil {
		return err
	}
	runCommand("mkdir", containerScan.tempDir)
	_, stdErr, retVal := runCommand("tar", "-xf", containerScan.tempDir+".tar", "-C"+containerScan.tempDir)
	if retVal != 0 {
		return errors.New(stdErr)
	}
	runCommand("rm", containerScan.tempDir+".tar")
	return nil
}

// Function to scan extracted layers of container file system for IOC file by file
// @parameters
// containerScan - Structure with details of the container  to scan
// @returns
// []output.IOCFound - List of all IOC found
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) scanPath(ctx *tasks.ScanContext, scanner *Scanner, containerPath string) ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	err := scanner.ScanIOCInDir("", "", "/fenced/mnt/host/"+containerPath, nil, &iocsFound, true, ctx)
	if err != nil {
		log.Errorf("findIOCInContainer: %s", err)
		return iocsFound, err
	}
	return iocsFound, nil
}

func (containerScan *ContainerScan) scanPathStream(ctx *tasks.ScanContext, scanner *Scanner, containerPath string) (chan output.IOCFound, error) {
	return scanner.ScanIOCInDirStream("", "", "/fenced/mnt/host/"+containerPath, nil, true, ctx)
}

// Function to scan extracted layers of container file system for IOC file by file
// @parameters
// containerScan - Structure with details of the container  to scan
// @returns
// []output.IOCFound - List of all IOC found
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) scan(ctx *tasks.ScanContext, scanner *Scanner) ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	err := scanner.ScanIOCInDir("", "", containerScan.tempDir, nil, &iocsFound, false, ctx)
	if err != nil {
		log.Errorf("findIOCInContainer: %s", err)
		return iocsFound, err
	}
	return iocsFound, nil
}
func (containerScan *ContainerScan) scanStream(ctx *tasks.ScanContext, scanner *Scanner) (chan output.IOCFound, error) {
	return scanner.ScanIOCInDirStream("", "", containerScan.tempDir, nil, false, ctx)
}

type ContainerExtractionResult struct {
	IOC         []output.IOCFound
	ContainerId string
}

func GetFileSystemPathsForContainer(runtime string, containerId string, namespace string) ([]byte, error) {
	// fmt.Println(append([]string{"docker"},  "|", "jq" , "-r" , "'map([.Name, .GraphDriver.Data.MergedDir]) | .[] | \"\\(.[0])\\t\\(.[1])\"'"))
	return exec.Command(runtime, "inspect", strings.TrimSpace(containerId)).Output()
}

func (s *Scanner) ExtractAndScanContainer(ctx *tasks.ScanContext, containerId string, namespace string) ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	tempDir, err := core.GetTmpDir(containerId, *s.TempDirectory)
	if err != nil {
		return iocsFound, err
	}
	defer core.DeleteTmpDir(tempDir)

	containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace}
	containerRuntime, _, err := vessel.AutoDetectRuntime()
	switch containerRuntime {
	case vesselConstants.DOCKER, vesselConstants.PODMAN:
		containerPath, err := GetFileSystemPathsForContainer(containerRuntime, containerId, namespace)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(containerPath), "\"MergedDir\":") {
			if strings.Contains(strings.Split(string(containerPath), "\"MergedDir\": \"")[1], "/merged\"") {
				containerPathToScan := strings.Split(strings.Split(string(containerPath), "\"MergedDir\": \"")[1], "/merged\"")[0] + "/merged"
				fmt.Println("Container Scan Path", containerPathToScan)
				iocsFound, err = containerScan.scanPath(ctx, s, containerPathToScan)
			}
		}
	case vesselConstants.CONTAINERD, vesselConstants.CRIO:
		err = containerScan.extractFileSystem()
		if err != nil {
			return nil, err
		}
		iocsFound, err = containerScan.scan(ctx, s)
		if err != nil {
			return iocsFound, err
		}
	}
	return iocsFound, nil
}

func (s *Scanner) ExtractAndScanContainerStream(ctx *tasks.ScanContext, containerId string, namespace string) (chan output.IOCFound, error) {
	tempDir, err := core.GetTmpDir(containerId, *s.TempDirectory)

	if err != nil {
		return nil, err
	}
	res := make(chan output.IOCFound, output_channel_size)

	go func() {
		defer core.DeleteTmpDir(tempDir)
		defer close(res)

		var middle chan output.IOCFound
		containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace}
		containerRuntime, _, err := vessel.AutoDetectRuntime()
		switch containerRuntime {
		case vesselConstants.DOCKER, vesselConstants.PODMAN:
			containerPath, err := GetFileSystemPathsForContainer(containerRuntime, containerId, namespace)
			if err != nil {
				return
			}
			if strings.Contains(string(containerPath), "\"MergedDir\":") {
				if strings.Contains(strings.Split(string(containerPath), "\"MergedDir\": \"")[1], "/merged\"") {
					containerPathToScan := strings.Split(strings.Split(string(containerPath), "\"MergedDir\": \"")[1], "/merged\"")[0] + "/merged"
					fmt.Println("Container Scan Path", containerPathToScan)
					middle, err = containerScan.scanPathStream(ctx, s, containerPathToScan)
					if err != nil {
						return
					}
				}
			}
		case vesselConstants.CONTAINERD, vesselConstants.CRIO:
			err = containerScan.extractFileSystem()
			if err != nil {
				return
			}

			middle, err = containerScan.scanStream(ctx, s)
			if err != nil {
				return
			}
		}
		for i := range middle {
			res <- i
		}
	}()
	return res, nil
}
