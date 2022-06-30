package main

// ------------------------------------------------------------------------------
// MIT License

// Copyright (c) 2020 deepfence

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
	"fmt"

	"github.com/deepfence/IOCScanner/core"
	"github.com/deepfence/IOCScanner/output"
	"github.com/deepfence/IOCScanner/scan"
	"github.com/deepfence/IOCScanner/server"
	"github.com/fatih/color"
	yr "github.com/hillu/go-yara/v4"
)

const (
	PLUGIN_NAME = "IOCScanner"
)

var (
	socketPath = flag.String("socket-path", "", "The gRPC server unix socket path")
	httpPort   = flag.String("http-port", "", "When set the http server will come up at port with df es as output")
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
var session = core.GetSession()

//defining a type fileScanner
type fileScanner struct {
	RuleFiles      []string `yaml:"rule-files"`
	FailOnWarnings bool     `yaml:"fail-on-warnings"`
	rules          *yr.Rules
}

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
	jsonImageIOCOutput := output.JsonImageIOCOutput{ImageName: image}
	jsonImageIOCOutput.SetTime()
	jsonImageIOCOutput.SetImageId(res.ImageId)
	jsonImageIOCOutput.PrintJsonHeader()
	jsonImageIOCOutput.PrintJsonFooter()
	jsonImageIOCOutput.SetIOC(res.IOCs)

	return &jsonImageIOCOutput, nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func findIOCInDir(dir string) (*output.JsonDirIOCOutput, error) {
	var isFirstIOC bool = true
	var numIOC uint = 0

	IOC, err := scan.ScanIOCInDir("", "", dir, &isFirstIOC, &numIOC, nil)
	if err != nil {
		core.GetSession().Log.Error("findIOCInDir: %s", err)
		return nil, err
	}

	jsonDirIOCOutput := output.JsonDirIOCOutput{DirName: *session.Options.Local}
	jsonDirIOCOutput.SetTime()
	jsonDirIOCOutput.PrintJsonHeader()
	jsonDirIOCOutput.PrintJsonFooter()
	jsonDirIOCOutput.SetIOC(IOC)

	return &jsonDirIOCOutput, nil
}

// Scan a container for IOC
// @parameters
// containerId - Id of the container to scan (e.g. "0fdasf989i0")
// @returns
// Error, if any. Otherwise, returns nil
func findIOCInContainer(containerId string, containerNS string) (*output.JsonImageIOCOutput, error) {
	res, err := scan.ExtractAndScanContainer(containerId, containerNS)
	if err != nil {
		return nil, err
	}
	jsonImageIOCOutput := output.JsonImageIOCOutput{ContainerId: containerId}
	jsonImageIOCOutput.SetTime()
	jsonImageIOCOutput.SetImageId(res.ContainerId)
	jsonImageIOCOutput.PrintJsonHeader()
	jsonImageIOCOutput.PrintJsonFooter()
	jsonImageIOCOutput.SetIOC(res.IOC)

	return &jsonImageIOCOutput, nil
}

type IOCWriter interface {
	WriteIOC(jsonFilename string) error
}

func runOnce() {
	var jsonOutput IOCWriter
	var err error
	var input string

	// Scan container image for IOC
	if len(*session.Options.ImageName) > 0 {
		fmt.Printf("Scanning image %s for IOC...\n", *session.Options.ImageName)
		jsonOutput, err = findIOCInImage(*session.Options.ImageName)
		if err != nil {
			core.GetSession().Log.Error("error scanning the image: %s", err)
			return
		}
	}

	// Scan local directory for IOC
	if len(*session.Options.Local) > 0 {
		fmt.Printf("[*] Scanning local directory: %s\n", color.BlueString(*session.Options.Local))
		jsonOutput, err = findIOCInDir(*session.Options.Local)
		if err != nil {
			core.GetSession().Log.Error("error scanning the dir: %s", err)
			return
		}
	}

	// Scan existing container for IOC
	if len(*session.Options.ContainerId) > 0 {
		fmt.Printf("Scanning container %s for IOC...\n", *session.Options.ContainerId)
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

	jsonFilename, err := core.GetJsonFilepath(input)
	if err != nil {
		core.GetSession().Log.Error("error while retrieving json output: %s", err)
		return
	}
	err = jsonOutput.WriteIOC(jsonFilename)
	if err != nil {
		core.GetSession().Log.Error("error while writing IOC: %s", err)
		return
	}
}

func main() {
	flag.Parse()

	if *socketPath != "" {
		//err := server.RunServer(*socketPath, PLUGIN_NAME)
		//if err != nil {
		//	core.GetSession().Log.Error("main: failed to serve: %v", err)
		//}
	} else if *httpPort != "" {
		err := server.RunHttpServer(*httpPort)
		if err != nil {
			core.GetSession().Log.Error("main: failed to serve through http: %v", err)
		}
	} else {
		runOnce()
	}
}
