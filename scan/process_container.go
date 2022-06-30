package scan

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deepfence/IOCScanner/core"
	"github.com/deepfence/IOCScanner/output"
	"github.com/deepfence/vessel"
	vesselConstants "github.com/deepfence/vessel/constants"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	dockerRuntime "github.com/deepfence/vessel/docker"
)

var (
	containerTarFileName = "save-output.tar"
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
		fmt.Println("Error: Could not detect container runtime")
		os.Exit(1)
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
func (containerScan *ContainerScan) scan() ([]output.IOCFound, error) {
	var isFirstIOC bool = true
	var numIOC uint = 0

	IOC, err := ScanIOCInDir("", "", containerScan.tempDir, &isFirstIOC, &numIOC, nil)
	if err != nil {
		core.GetSession().Log.Error("findIOCInContainer: %s", err)
		return nil, err
	}

	for _, ioc := range IOC {
		ioc.CompleteFilename = strings.Replace(ioc.CompleteFilename, containerScan.tempDir, "", 1)
	}

	return IOC, nil
}

type ContainerExtractionResult struct {
	IOC         []output.IOCFound
	ContainerId string
}

func ExtractAndScanContainer(containerId string, namespace string) (*ContainerExtractionResult, error) {
	tempDir, err := core.GetTmpDir(containerId)
	if err != nil {
		return nil, err
	}
	defer core.DeleteTmpDir(tempDir)

	containerScan := ContainerScan{containerId: containerId, tempDir: tempDir, namespace: namespace}
	err = containerScan.extractFileSystem()

	if err != nil {
		return nil, err
	}

	IOC, err := containerScan.scan()

	if err != nil {
		return nil, err
	}
	return &ContainerExtractionResult{ContainerId: containerScan.containerId, IOC: IOC}, nil
}
