package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
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
	scanStatusComplete       = "COMPLETE"
	scanStatusError          = "ERROR"
	defaultScanConcurrency   = 1
	malwareScanIndexName     = "malware-scan"
	malwareScanLogsIndexName = "malware-scan-logs"
)

var (
	scanConcurrency    int
	httpScanWorkerPool *tunny.Pool
)

type standaloneRequest struct {
	ImageNameWithTag string `json:"image_name_with_tag"`
}

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

func runMalwareScanStandalone(writer http.ResponseWriter, request *http.Request) {
	fmt.Printf("rbody: %s\n", request.Body)
	requestDump, err := httputil.DumpRequest(request, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	b, err := ioutil.ReadAll(request.Body)
	defer request.Body.Close()
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}

	// decoder := json.NewDecoder(request.Body)
	var req standaloneRequest
	// err = decoder.Decode(&req)
	err = json.Unmarshal(b, &req)
	if err != nil {
		fmt.Fprintf(writer, "Parse err: %v", err)
		return
	}

	fmt.Printf("Malware scan Scan triggered for %s: ", req.ImageNameWithTag)

	fmt.Printf("Malware Scan triggered for %s: ", req.ImageNameWithTag)
	res, err := scan.ExtractAndScanImage(req.ImageNameWithTag)
	if err != nil {
		fmt.Fprintf(writer, "Image scan err: %v", err)
		return
	}

	JsonImageIOCOutput := output.JsonImageIOCOutput{ImageName: req.ImageNameWithTag}
	JsonImageIOCOutput.SetTime()
	JsonImageIOCOutput.SetImageId(res.ImageId)
	JsonImageIOCOutput.PrintJsonHeader()
	JsonImageIOCOutput.PrintJsonFooter()
	JsonImageIOCOutput.SetIOC(res.IOCs)

	outByte, err := json.Marshal(JsonImageIOCOutput)
	if err != nil {
		fmt.Fprintf(writer, "report marshaling error: %v", err)
		return
	}

	fmt.Fprintf(writer, string(outByte))
	return

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
	out, err := runCommand(imageSaveCommand, "Image Save:"+imageName)
	fmt.Println("Output from python save:" + out.String())
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
	byteJson, err := format(malwareScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling malware in_progress log object to json:" + err.Error())
	} else {
		err = output.IngestMalwareScanResults(string(byteJson), malwareScanLogsIndexName)
		if err != nil {
			fmt.Println("Error in updating in_progress log" + err.Error())
		}
	}
	fmt.Println("extracting scans")
	res, err := scan.ExtractAndScanFromTar(tempDir, imageName)
	if err != nil {
		malwareScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := format(malwareScanLogDoc)
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
		byteJson, err := format(malwareScanDoc)
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
	byteJson, err = format(malwareScanLogDoc)
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
	core.GetSession().Log.Info("Http Server listening before ")
	http.ListenAndServe(":"+listenPort, nil)
	core.GetSession().Log.Info("Http Server listening on " + listenPort)
	return nil
}

func RunStandaloneHttpServer(listenPort string) error {
	fmt.Println("Trying to start Http Server on " + listenPort)
	http.Handle("/malware-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		core.GetSession().Log.Info("Entered scan")
		runMalwareScanStandalone(writer, request)
	}))
	http.HandleFunc("/malware-scan/ping", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "Connection is successful")
	})
	core.GetSession().Log.Info("Http Server listening before ")
	http.ListenAndServe(":"+listenPort, nil)
	core.GetSession().Log.Info("Http Server listening on " + listenPort)
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

func format(data map[string]interface{}) ([]byte, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	value := "{\"value\":" + string(encoded) + "}"
	return []byte("{\"records\":[" + value + "]}"), nil
}
