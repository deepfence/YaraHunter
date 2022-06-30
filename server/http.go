package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/IOCScanner/core"
	"github.com/deepfence/IOCScanner/output"
	"github.com/deepfence/IOCScanner/scan"
)

const (
	scanStatusComplete     = "COMPLETE"
	scanStatusError        = "ERROR"
	defaultScanConcurrency = 5
	iocScanIndexName       = "ioc-scan"
	iocScanLogsIndexName   = "ioc-scan-logs"
)

var (
	scanConcurrency    int
	httpScanWorkerPool *tunny.Pool
)

type imageParameters struct {
	imageName string
	scanId    string
	form      url.Values
}

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("IOC_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = defaultScanConcurrency
	}
	httpScanWorkerPool = tunny.NewFunc(scanConcurrency, processImageWrapper)
}

func runIOCScan(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		fmt.Fprintf(writer, "ParseForm() err: %v", err)
		return
	} else if request.PostForm.Get("image_name_with_tag_list") == "" {
		http.Error(writer, "{\"error\":\"Image Name with tag list is required \"}", http.StatusConflict)
	} else {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "{\"status\": \"Scan Queued\"}")
		go processScans(request.PostForm)
	}
}

func processScans(form url.Values) {
	imageNameList := form["image_name_with_tag_list"]
	for index, imageName := range imageNameList {
		go httpScanWorkerPool.Process(imageParameters{imageName: imageName, scanId: form["scan_id_list"][index], form: form})
	}
}

func processImageWrapper(imageParamsInterface interface{}) interface{} {
	imageParams, ok := imageParamsInterface.(imageParameters)
	if !ok {
		fmt.Println("Error reading input from API")
		return nil
	}
	processImage(imageParams.imageName, imageParams.scanId, imageParams.form)
	return nil
}

func processImage(imageName string, scanId string, form url.Values) {
	tempFolder, err := core.GetTmpDir(imageName)
	if err != nil {
		fmt.Println("error creating temp dirs:" + err.Error())
		return
	}
	imageSaveCommand := exec.Command("python3", "/home/deepfence/usr/registry_image_save.py", "--image_name_with_tag", imageName, "--registry_type", form.Get("registry_type"),
		"--mgmt_console_url", output.MgmtConsoleUrl, "--deepfence_key", output.DeepfenceKey, "--credential_id", form.Get("credential_id"),
		"--output_folder", tempFolder)
	_, err = runCommand(imageSaveCommand, "Image Save:"+imageName)
	if err != nil {
		fmt.Println("error saving image:" + err.Error())
		return
	}
	scanAndPublish(imageName, scanId, tempFolder, form)
}

func scanAndPublish(imageName string, scanId string, tempDir string, postForm url.Values) {
	var iocScanLogDoc = make(map[string]interface{})
	iocScanLogDoc["scan_status"] = "IN_PROGRESS"
	iocScanLogDoc["node_id"] = imageName
	iocScanLogDoc["node_name"] = imageName
	iocScanLogDoc["time_stamp"] = core.GetTimestamp()
	iocScanLogDoc["@timestamp"] = core.GetCurrentTime()
	iocScanLogDoc["scan_id"] = scanId
	for key, value := range postForm {
		if len(value) > 0 {
			iocScanLogDoc[key] = value[0]
		}
	}
	iocScanLogDoc["image_name_with_tag_list"] = nil
	iocScanLogDoc["scan_id_list"] = nil
	byteJson, err := json.Marshal(iocScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling ioc log object to json:" + err.Error())
	} else {
		err = output.IngestIOCScanResults(string(byteJson), iocScanLogsIndexName)
		if err != nil {
			fmt.Println("Error in updating in_progress log" + err.Error())
		}
	}
	res, err := scan.ExtractAndScanFromTar(tempDir, imageName)
	if err != nil {
		iocScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := json.Marshal(iocScanLogDoc)
		if err != nil {
			fmt.Println("Error in marshalling ioc scan result object to json:" + err.Error())
			return
		}
		err = output.IngestIOCScanResults(string(byteJson), iocScanLogsIndexName)
		if err != nil {
			fmt.Println("error ingesting data: " + err.Error())
		}
		return
	}
	timestamp := core.GetTimestamp()
	currTime := core.GetCurrentTime()
	for _, ioc := range res.IOCs {
		var iocScanDoc = make(map[string]interface{})
		for key, value := range postForm {
			if len(value) > 0 {
				iocScanDoc[key] = value[0]
			}
		}
		iocScanDoc["image_name_with_tag_list"] = nil
		iocScanDoc["scan_id_list"] = nil
		iocScanDoc["time_stamp"] = timestamp
		iocScanDoc["@timestamp"] = currTime
		iocScanDoc["node_id"] = imageName
		iocScanDoc["node_name"] = imageName
		iocScanDoc["scan_id"] = scanId
		iocScanDoc["severity"] = ioc.Severity
		iocScanDoc["file_name"] = ioc.CompleteFilename
		iocScanDoc["rule_name"] = ioc.RuleName
		iocScanDoc["matched_contents"] = ioc.MatchedContents
		iocScanDoc["strings_to_match"] = ioc.StringsToMatch
		byteJson, err := json.Marshal(iocScanDoc)
		if err != nil {
			fmt.Println("Error in marshalling ioc scan result object to json:" + err.Error())
			return
		}
		err = output.IngestIOCScanResults(string(byteJson), iocScanIndexName)
		if err != nil {
			fmt.Println("Error in sending data to iocScanIndex:" + err.Error())
		}
	}
	if err == nil {
		iocScanLogDoc["scan_status"] = scanStatusComplete
	} else {
		iocScanLogDoc["scan_status"] = scanStatusError
		iocScanLogDoc["scan_message"] = err.Error()
	}
	iocScanLogDoc["time_stamp"] = timestamp
	iocScanLogDoc["@timestamp"] = currTime
	byteJson, err = json.Marshal(iocScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling iocScanLogDoc to json:" + err.Error())
		return
	}
	err = output.IngestIOCScanResults(string(byteJson), iocScanLogsIndexName)
	if err != nil {
		fmt.Println("Error in sending data to iocScanLogsIndex:" + err.Error())
	}
}

func RunHttpServer(listenPort string) error {
	http.Handle("/ioc-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		runIOCScan(writer, request)
	}))
	http.HandleFunc("/ioc-scan/test", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "Hello World!")
	})
	fmt.Println("Http Server listening on " + listenPort)
	err := http.ListenAndServe(":"+listenPort, nil)
	if err != nil {
		return err
	}
	return nil
}

// operation is prepended to error message in case of error: optional
func runCommand(cmd *exec.Cmd, operation string) (*bytes.Buffer, error) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errorOnRun := cmd.Run()
	if errorOnRun != nil {
		return nil, errors.New(operation + fmt.Sprint(errorOnRun) + ": " + stderr.String())
	}
	return &out, nil
}
