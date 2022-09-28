package main

// ------------------------------------------------------------------------------
// MIT License

// Copyright (c) 2022 deepfence

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// ------------------------------------------------------------------------------

import (
	"flag"
	"strings"

	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/YaRadare/scan"
	"github.com/fatih/color"
)

const (
	PLUGIN_NAME = "MalwareScanner"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
var session = core.GetSession()

// Scan a container image for IOC layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func findIOCInImage(image string) (*output.JsonImageIOCOutput, error) {

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
func findIOCInDir(dir string) (*output.JsonDirIOCOutput, error) {
	var tempIOCsFound []output.IOCFound
	err := scan.ScanIOCInDir("", "", dir, nil, &tempIOCsFound)
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
func findIOCInContainer(containerId string, containerNS string) (*output.JsonImageIOCOutput, error) {
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

type IOCWriter interface {
	WriteIOC(jsonFilename string) error
}

func runOnce() {
	var jsonOutput IOCWriter
	var err error

	// Scan container image for IOC
	if len(*session.Options.ImageName) > 0 {
		session.Log.Info("Scanning image %s for IOC...\n", *session.Options.ImageName)
		jsonOutput, err = findIOCInImage(*session.Options.ImageName)
		if err != nil {
			core.GetSession().Log.Error("error scanning the image: %s", err)
			return
		}
	}

	// Scan local directory for IOC
	if len(*session.Options.Local) > 0 {
		session.Log.Info("[*] Scanning local directory: %s\n", color.BlueString(*session.Options.Local))
		jsonOutput, err = findIOCInDir(*session.Options.Local)
		if err != nil {
			core.GetSession().Log.Error("error scanning the dir: %s", err)
			return
		}
	}

	// Scan existing container for IOC
	if len(*session.Options.ContainerId) > 0 {
		session.Log.Info("Scanning container %s for IOC...\n", *session.Options.ContainerId)
		jsonOutput, err = findIOCInContainer(*session.Options.ContainerId, *session.Options.ContainerNS)
		if err != nil {
			core.GetSession().Log.Error("error scanning the container: %s", err)
			return
		}
	}

	if jsonOutput == nil {
		core.GetSession().Log.Error("set either -local or -image-name flag")
		return
	}

	jsonFilename, err := core.GetJsonFilepath()
	if err != nil {
		core.GetSession().Log.Error("error while retrieving json output: %s", err)
		return
	}
	if jsonFilename != "" {
		err = jsonOutput.WriteIOC(jsonFilename)
		if err != nil {
			core.GetSession().Log.Error("error while writing IOC: %s", err)
			return
		}
	}
}

func main() {
	flag.Parse()
	core.GetSession().Log.Info("server inside23 port", *session.Options)
	if *session.Options.SocketPath != "" {
		err := server.RunServer(*session.Options.SocketPath, PLUGIN_NAME)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve: %v", err)
		}
	} else if *session.Options.HttpPort != "" {
		core.GetSession().Log.Info("server inside port")
		err := server.RunHttpServer(*session.Options.HttpPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else if *session.Options.StandAloneHttpPort != "" {
		core.GetSession().Log.Info("server inside port")
		err := server.RunStandaloneHttpServer(*session.Options.StandAloneHttpPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else {
		runOnce()
	}

	runOnce()
}
