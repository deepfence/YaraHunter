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
	"reflect"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/YaRadare/core"
	"github.com/deepfence/YaRadare/output"
	"github.com/deepfence/YaRadare/scan"
)

const (
	scanStatusComplete      = "COMPLETE"
	scanStatusError         = "ERROR"
	defaultScanConcurrency  = 5
	malwareScanIndexName     = "malware-scan"
	malwareScanLogsIndexName = "malware-scan-logs"
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
	scanConcurrency, err = strconv.Atoi(os.Getenv("MALWARE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = defaultScanConcurrency
	}
	httpScanWorkerPool = tunny.NewFunc(scanConcurrency, processImageWrapper)
}

func runMalwareScan(writer http.ResponseWriter, request *http.Request) {
	core.GetSession().Log.Info("entered into scan here")
	fmt.Println(writer,request)
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
	var malwareScanLogDoc = make(map[string]interface{})
	malwareScanLogDoc["scan_status"] = "IN_PROGRESS"
	malwareScanLogDoc["node_id"] = imageName
	malwareScanLogDoc["node_name"] = imageName
	malwareScanLogDoc["time_stamp"] = core.GetTimestamp()
	malwareScanLogDoc["@timestamp"] = core.GetCurrentTime()
	malwareScanLogDoc["scan_id"] = scanId
	for key, value := range postForm {
		if len(value) > 0 {
			malwareScanLogDoc[key] = value[0]
		}
	}
	malwareScanLogDoc["image_name_with_tag_list"] = nil
	malwareScanLogDoc["scan_id_list"] = nil
	byteJson, err := json.Marshal(malwareScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling malware in_progress log object to json:" + err.Error())
	} else {
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
		if err != nil {
			fmt.Println("Error in updating in_progress log" + err.Error())
		}
	}
	res, err := scan.ExtractAndScanFromTar(tempDir, imageName)
	if err != nil {
		malwareScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := json.Marshal(malwareScanLogDoc)
		if err != nil {
			fmt.Println("Error in marshalling malware result object to json:" + err.Error())
			return
		}
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
		if err != nil {
			fmt.Println("error ingesting data: " + err.Error())
		}
		return
	}
	timestamp := core.GetTimestamp()
	currTime := core.GetCurrentTime()
	malwares := output.MalwaresToMalwareInfos(res.IOCs)
	for _, malware := range malwares {
		var malwareScanDoc = make(map[string]interface{})
		for key, value := range postForm {
			if len(value) > 0 {
				malwareScanDoc[key] = value[0]
			}
		}
		malwareScanDoc["image_name_with_tag_list"] = nil
		malwareScanDoc["scan_id_list"] = nil
		malwareScanDoc["time_stamp"] = timestamp
		malwareScanDoc["@timestamp"] = currTime
		malwareScanDoc["node_id"] = imageName
		malwareScanDoc["node_name"] = imageName
		malwareScanDoc["scan_id"] = scanId
		values := reflect.ValueOf(*malware)
		typeOfS := values.Type()
		for index := 0; index < values.NumField(); index++ {
			if values.Field(index).CanInterface() {
				malwareScanDoc[typeOfS.Field(index).Name] = values.Field(index).Interface()
			}
		}
		byteJson, err := json.Marshal(malwareScanDoc)
		if err != nil {
			fmt.Println("Error in marshalling malware result object to json:" + err.Error())
			return
		}
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanIndexName)
		if err != nil {
			fmt.Println("Error in sending data to malwareScanIndex:" + err.Error())
		}
	}
	if err == nil {
		malwareScanLogDoc["scan_status"] = scanStatusComplete
	} else {
		malwareScanLogDoc["scan_status"] = scanStatusError
		malwareScanLogDoc["scan_message"] = err.Error()
	}
	malwareScanLogDoc["time_stamp"] = timestamp
	malwareScanLogDoc["@timestamp"] = currTime
	byteJson, err = json.Marshal(malwareScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling malwareScanLogDoc to json:" + err.Error())
		return
	}
	err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
	if err != nil {
		fmt.Println("Error in sending data to malwareScanLogsIndex:" + err.Error())
	}
}

func RunHttpServer(listenPort string) error {
	http.Handle("/malware-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		core.GetSession().Log.Info("Entered scan")
		runMalwareScan(writer, request)
	}))
	http.HandleFunc("/malware-scan/test", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "Hello World!")
	})

	http.ListenAndServe(":"+listenPort, nil)
	fmt.Println("Http Server listening on " + listenPort)
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
