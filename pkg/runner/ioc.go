package runner

import (
	"strings"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	log "github.com/sirupsen/logrus"
)

// Scan a container image for IOC layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInImage(ctx *tasks.ScanContext, scanner *scan.Scanner) (*output.JsonImageIOCOutput, error) {
	res, err := scanner.ExtractAndScanImage(ctx, *scanner.ImageName)
	if err != nil {
		return nil, err
	}
	jsonImageIOCOutput := output.JsonImageIOCOutput{ImageName: *scanner.ImageName, IOC: res.IOCs}
	jsonImageIOCOutput.SetTime()
	jsonImageIOCOutput.SetImageId(res.ImageId)
	jsonImageIOCOutput.SetIOC(res.IOCs)

	return &jsonImageIOCOutput, nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInDir(ctx *tasks.ScanContext, scanner *scan.Scanner) (*output.JsonDirIOCOutput, error) {
	dirName := *scanner.Local
	var tempIOCsFound []output.IOCFound
	err := scanner.ScanIOCInDir("", "", dirName, nil, &tempIOCsFound, false, ctx)
	if err != nil {
		log.Errorf("findIOCInDir: %s", err)
		return nil, err
	}
	hostMountPath := *scanner.HostMountPath
	if hostMountPath != "" {
		dirName = strings.TrimPrefix(dirName, hostMountPath)
	}
	jsonDirIOCOutput := output.JsonDirIOCOutput{DirName: dirName, IOC: tempIOCsFound}
	jsonDirIOCOutput.SetTime()

	return &jsonDirIOCOutput, nil
}

// Scan a container for IOC
// @parameters
// containerId - Id of the container to scan (e.g. "0fdasf989i0")
// @returns
// Error, if any. Otherwise, returns nil
func FindIOCInContainer(ctx *tasks.ScanContext, scanner *scan.Scanner) (*output.JsonImageIOCOutput, error) {
	var tempIOCsFound []output.IOCFound
	tempIOCsFound, err := scanner.ExtractAndScanContainer(ctx, *scanner.ContainerId, *scanner.ContainerNS)
	if err != nil {
		return nil, err
	}
	jsonImageIOCOutput := output.JsonImageIOCOutput{ContainerId: *scanner.ContainerId, IOC: tempIOCsFound}
	jsonImageIOCOutput.SetTime()

	return &jsonImageIOCOutput, nil
}
