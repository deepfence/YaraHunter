package scan

import (
	"errors"
	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/vessel"
	vesselConstants "github.com/deepfence/vessel/constants"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	dockerRuntime "github.com/deepfence/vessel/docker"
	"os/exec"
	"strings"
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
		containerRuntimeInterface = dockerRuntime.New()
	case vesselConstants.CONTAINERD:
		containerRuntimeInterface = containerdRuntime.New(endpoint)
	}
	if containerRuntimeInterface == nil {
		return errors.New("could not detect container runtime")
	}
	err = containerRuntimeInterface.ExtractFileSystemContainer(containerScan.containerId, containerScan.namespace, containerScan.tempDir+".tar", endpoint)

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
func (containerScan *ContainerScan) scanPath(containerPath string) ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	err := ScanIOCInDir("", "", containerPath, nil, &iocsFound, true)
	if err != nil {
		core.GetSession().Log.Error("findIOCInContainer: %s", err)
		return iocsFound, err
	}
	return iocsFound, nil
}

// Function to scan extracted layers of container file system for IOC file by file
// @parameters
// containerScan - Structure with details of the container  to scan
// @returns
// []output.IOCFound - List of all IOC found
// Error - Errors, if any. Otherwise, returns nil
func (containerScan *ContainerScan) scan() ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	err := ScanIOCInDir("", "", containerScan.tempDir, nil, &iocsFound,false)
	if err != nil {
		core.GetSession().Log.Error("findIOCInContainer: %s", err)
		return iocsFound, err
	}
	return iocsFound, nil
}

type ContainerExtractionResult struct {
	IOC         []output.IOCFound
	ContainerId string
}

func  GetFileSystemPathsForContainer(containerId string, namespace string) ([]byte, error) {
	return exec.Command("docker", "inspect", strings.TrimSpace(containerId), "|", "jq" , "-r" , "'map([.Name, .GraphDriver.Data.MergedDir]) | .[] | \"\\(.[0])\t\\(.[1])\"'").Output()
}

func ExtractAndScanContainer(containerId string, namespace string) ([]output.IOCFound, error) {
	var iocsFound []output.IOCFound
	tempDir, err := core.GetTmpDir(containerId)
	if err != nil {
		return iocsFound, err
	}
	defer core.DeleteTmpDir(tempDir)

	containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace}
	containerRuntime, _, err := vessel.AutoDetectRuntime()
	switch containerRuntime {
	case vesselConstants.DOCKER:
		containerPath, err := GetFileSystemPathsForContainer(containerId, namespace) 
		if err != nil {
			return nil, err
		}
		iocsFound, err = containerScan.scanPath(strings.TrimSpace(string(containerPath)))
	case vesselConstants.CONTAINERD:
		containerScan.extractFileSystem()
		err = containerScan.extractFileSystem()
		if err != nil {
			return nil, err
		}

		iocsFound, err = containerScan.scan()
		if err != nil {
			return iocsFound, err
		}
	}
	return iocsFound, nil
}

