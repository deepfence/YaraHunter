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
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/YaRadare/scan"
	"github.com/deepfence/YaRadare/server"
	"github.com/fatih/color"
)

type YaraRuleDetail struct {
	Built    time.Time `json:"built"`
	Version  int       `json:"version"`
	URL      string    `json:"url"`
	Checksum string    `json:"checksum"`
}

type YaraRuleListingV3 struct {
	V3 []YaraRuleDetail `json:"3"`
}

type YaraRuleListing struct {
	Available YaraRuleListingV3 `json:"available"`
}

type YaraRuleUpdater struct {
	yaraRuleListingJson  YaraRuleListing
	yaraRulePath         string
	downloadYaraRulePath string
	currentFileChecksum  string
	currentFilePath      string
	sync.RWMutex
}

const (
	PLUGIN_NAME = "MalwareScanner"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for IOC
var session = core.GetSession()

var wg sync.WaitGroup

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

func sha256sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return false
}

func NewYaraRuleUpdater() (error, *YaraRuleUpdater) {
	updater := &YaraRuleUpdater{
		yaraRuleListingJson:  YaraRuleListing{},
		yaraRulePath:         path.Join(*core.GetSession().Options.RulesPath, "metaListingData.json"),
		downloadYaraRulePath: "",
	}
	if fileExists(updater.yaraRulePath) {
		content, err := os.ReadFile(updater.yaraRulePath)
		if err != nil {
			return err, nil
		}
		err = json.Unmarshal(content, &updater)
		if err != nil {
			return err, nil
		}
	}
	return nil, updater
}

func untar(d *os.File, r io.Reader) error {

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}
		// the target location where the dir/file should be created
		// target := filepath.Join(dst, strings.Replace(header.Name,"yara-rules/", "", -1))
		// fmt.Println("the target main is", header.Name,strings.Replace(header.Name,"yara-rules/", "", -1))
		// fmt.Println("the target is", target)
		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type
		switch header.Typeflag {
		// if its a dir and it doesn't exist create it
		// if it's a file create it
		case tar.TypeReg:
			//fmt.Println("the j is", header.Name)
			if strings.Contains(header.Name, ".yar") {

				if _, err := io.Copy(d, tr); err != nil {
					fmt.Println("copying err", err)
					return err
				}

				// manually close here after each file operation; defering would cause each file close
				// to wait until all operations have completed.
				d.Close()
			}

		}
	}
}

func createFile(dest string) (error, *os.File) {
	// Create blank file
	file, err := os.Create(filepath.Join(dest, "malware.yar"))
	if err != nil {
		fmt.Println("test why error", err)
		return err, nil
	}
	return nil, file
}

func downloadFile(dUrl string, dest string) (error, string) {
	//fmt.Println("the dynamic url is",dUrl)
	fullUrlFile := dUrl

	// Build fileName from fullPath
	fileURL, err := url.Parse(fullUrlFile)
	if err != nil {
		return err, ""
	}
	//fmt.Println("the dynamic url is",fileURL)
	path := fileURL.Path
	segments := strings.Split(path, "/")
	fileName := segments[len(segments)-1]

	// Create blank file
	file, err := os.Create(filepath.Join(dest, fileName))
	if err != nil {
		return err, ""
	}
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	// Put content on file
	resp, err := client.Get(fullUrlFile)
	//fmt.Println(" The dynamic url is ",fileName)
	if err != nil {
		return err, ""
	}
	defer resp.Body.Close()

	size, err := io.Copy(file, resp.Body)
	fmt.Println("copied size", size)
	if err != nil {
		return err, ""
	}
	//fmt.Println("the dynamic url is",fileURL)
	defer file.Close()
	return nil, fileName

}

func writeToFile(dUrl string, dest string) error {
	fullUrlFile := dUrl

	// Build fileName from fullPath
	fileURL, err := url.Parse(fullUrlFile)
	if err != nil {
		return err
	}
	path := fileURL.Path
	segments := strings.Split(path, "/")
	fileName := segments[len(segments)-1]

	// Create blank file
	file, err := os.Create(filepath.Join(dest, fileName))
	if err != nil {
		return err
	}
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	// Put content on file
	resp, err := client.Get(fullUrlFile)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	size, err := io.Copy(file, resp.Body)
	fmt.Println("copied size", size)
	if err != nil {
		return err
	}

	defer file.Close()
	return nil

}

func runYaraUpdate() error {
	err, yaraRuleUpdater := NewYaraRuleUpdater()
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	downloadError, _ := downloadFile("https://threat-intel.deepfence.io/yara-rules/listing.json", *core.GetSession().Options.ConfigPath)
	if downloadError != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", downloadError)
		return err
	}
	content, err := os.ReadFile(filepath.Join(*core.GetSession().Options.ConfigPath, "/listing.json"))
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	var yaraRuleListingJson YaraRuleListing
	err = json.Unmarshal(content, &yaraRuleListingJson)
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	if len(yaraRuleListingJson.Available.V3) > 0 {
		if yaraRuleListingJson.Available.V3[0].Checksum != yaraRuleUpdater.currentFileChecksum {
			yaraRuleUpdater.currentFileChecksum = yaraRuleListingJson.Available.V3[0].Checksum
			file, _ := json.MarshalIndent(yaraRuleUpdater, "", " ")
			writeErr := os.WriteFile(path.Join(*core.GetSession().Options.RulesPath, "metaListingData.json"), file, 0644)

			if writeErr != nil {
				core.GetSession().Log.Error("main: failed to serve: %v", writeErr)
				return writeErr
			}
			downloadError, fileName := downloadFile(yaraRuleListingJson.Available.V3[0].URL, *core.GetSession().Options.ConfigPath)
			//fmt.Println("reached here 5 times", fileName)

			if downloadError != nil {
				core.GetSession().Log.Error("main: failed to serve: %v", downloadError)
				return downloadError
			}
			if fileExists(filepath.Join(*core.GetSession().Options.ConfigPath, fileName)) {
				fmt.Println("the file exists")

				readFile, readErr := os.OpenFile(filepath.Join(*core.GetSession().Options.ConfigPath, fileName), os.O_CREATE|os.O_RDWR, 0755)
				if readErr != nil {
					core.GetSession().Log.Error("main: failed to serve: %v", readErr)
					return readErr
				}
				createErr, newFile := createFile(*core.GetSession().Options.ConfigPath)
				if createErr != nil {
					core.GetSession().Log.Error("main: failed to create: %v", createErr)
					return createErr
				}
				//fmt.Println("the new file created is",newFile)
				unTarErr := untar(newFile, readFile)
				if unTarErr != nil {
					core.GetSession().Log.Error("main: failed to serve: %v", unTarErr)
					return unTarErr
				}
				session = core.GetSession()
				defer newFile.Close()
				defer readFile.Close()

			}

		}
	}
	return nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func findIOCInDir(dir string) (*output.JsonDirIOCOutput, error) {
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

func yaraUpdate(newwg *sync.WaitGroup) {
	defer newwg.Done()
	if *session.Options.SocketPath != "" && *session.Options.HttpPort != "" {
		flag.Parse()
		fmt.Println("Go Tickers Tutorial")
		// this creates a new ticker which will
		// `tick` every 1 second.
		ticker := time.NewTicker(10 * time.Hour)

		// for every `tick` that our `ticker`
		// emits, we print `tock`
		for t := range ticker.C {
			fmt.Println("Invoked at ", t)
			err := runYaraUpdate()
			if err != nil {
				core.GetSession().Log.Fatal("main: failed to serve: %v", err)
			}
		}
	}
}

func yaraResults(newwg *sync.WaitGroup) {
	defer newwg.Done()
	flag.Parse()
	err := runYaraUpdate()
	if err != nil {
		core.GetSession().Log.Fatal("main: failed to serve: %v", err)
	}
	if *session.Options.SocketPath != "" {
		fmt.Println("reached inside server")
		//core.GetSession().Log.Info("reached inside server")
		err := server.RunServer(*session.Options.SocketPath, PLUGIN_NAME)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve: %v", err)
		}
		//core.GetSession().Log.Info("reached at this point")
	} else if *session.Options.HttpPort != "" {
		core.GetSession().Log.Info("server inside port")
		fmt.Println("server inside port")
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

}

func main() {

	//fmt.Println(" Welcome to concurrency")
	wg.Add(2)
	go yaraUpdate(&wg)
	go yaraResults(&wg)
	//fmt.Println("Waiting To Finish")
	wg.Wait()
	//fmt.Println("\nTerminating Program")
	//f2(<-out1, <-out2)
}
