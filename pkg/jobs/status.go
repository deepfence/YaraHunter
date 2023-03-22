package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	scanStatusFilename = getDfInstallDir() + "/var/log/fenced/malware-scan-log/malware_scan_log.log"
)

func writeScanStatus(status, scan_id, scan_message string) {
	var scanLogDoc = make(map[string]interface{})
	scanLogDoc["scan_id"] = scan_id
	scanLogDoc["scan_status"] = status
	scanLogDoc["scan_message"] = scan_message

	byteJson, err := json.Marshal(scanLogDoc)
	if err != nil {
		fmt.Println("Error marshalling json for malware-logs-status: ", err)
		return
	}

	err = writeScanDataToFile(string(byteJson), scanStatusFilename)
	if err != nil {
		fmt.Println("Error in sending data to malware-logs-status to mark in progress:" + err.Error())
		return
	}
}

func writeScanDataToFile(malwareScanMsg string, filename string) error {
	os.MkdirAll(filepath.Dir(filename), 0755)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	malwareScanMsg = strings.Replace(malwareScanMsg, "\n", " ", -1)
	if _, err = f.WriteString(malwareScanMsg + "\n"); err != nil {
		return err
	}
	return nil
}

func getDfInstallDir() string {
	installDir, exists := os.LookupEnv("DF_INSTALL_DIR")
	if exists {
		return installDir
	} else {
		return ""
	}
}

func StartStatusReporter(ctx context.Context, scan_id string) chan error {
	res := make(chan error)
	startScanJob()
	go func() {
		defer stopScanJob()
		var err, abort error
	loop:
		for {
			select {
			case err = <-res:
				break loop
			case <-ctx.Done():
				abort = ctx.Err()
				break loop
			case <-time.After(30 * time.Second):
				writeScanStatus("IN_PROGRESS", scan_id, "")
			}
		}
		if abort != nil {
			writeScanStatus("CANCELLED", scan_id, abort.Error())
			return
		}
		if err != nil {
			writeScanStatus("ERROR", scan_id, err.Error())
			return
		}
		writeScanStatus("COMPLETE", scan_id, "")
	}()
	return res
}
