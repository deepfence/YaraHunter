package runner

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/deepfence/YaraHunter/core"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
)

// Scan a container image for IOC layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInImage(image string) (*output.JsonImageIOCOutput, error) {
	res, err := scan.ExtractAndScanImage(image)
	if err != nil {
		return nil, err
	}
	jsonImageIOCOutput := output.JsonImageIOCOutput{ImageName: image, IOC: res.IOCs}
	jsonImageIOCOutput.SetTime()
	jsonImageIOCOutput.SetImageId(res.ImageId)
	jsonImageIOCOutput.SetIOC(res.IOCs)
	jsonImageIOCOutput.PrintJsonHeader()
	var isFirstIOC bool = true
	output.PrintColoredIOC(res.IOCs, &isFirstIOC)

	jsonImageIOCOutput.PrintJsonFooter()

	return &jsonImageIOCOutput, nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInDir(dir string) (*output.JsonDirIOCOutput, error) {
	var tempIOCsFound []output.IOCFound
	err := scan.ScanIOCInDir("", "", dir, nil, &tempIOCsFound, false)
	if err != nil {
		core.GetSession().Log.Error("findIOCInDir: %s", err)
		return nil, err
	}
	dirName := *session.Options.Local
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		dirName = strings.TrimPrefix(dirName, hostMountPath)
	}
	jsonDirIOCOutput := output.JsonDirIOCOutput{DirName: dirName, IOC: tempIOCsFound}
	jsonDirIOCOutput.SetTime()
	jsonDirIOCOutput.PrintJsonHeader()
	var isFirstIOC bool = true
	output.PrintColoredIOC(jsonDirIOCOutput.IOC, &isFirstIOC)

	jsonDirIOCOutput.PrintJsonFooter()

	return &jsonDirIOCOutput, nil
}

// Scan a container for IOC
// @parameters
// containerId - Id of the container to scan (e.g. "0fdasf989i0")
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInContainer(containerId string, containerNS string) (*output.JsonImageIOCOutput, error) {
	var tempIOCsFound []output.IOCFound
	tempIOCsFound, err := scan.ExtractAndScanContainer(containerId, containerNS)
	if err != nil {
		return nil, err
	}
	jsonImageIOCOutput := output.JsonImageIOCOutput{ContainerId: containerId, IOC: tempIOCsFound}
	jsonImageIOCOutput.SetTime()
	jsonImageIOCOutput.PrintJsonHeader()
	var isFirstIOC bool = true
	output.PrintColoredIOC(jsonImageIOCOutput.IOC, &isFirstIOC)

	jsonImageIOCOutput.PrintJsonFooter()

	return &jsonImageIOCOutput, nil
}
