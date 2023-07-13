package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	log "github.com/sirupsen/logrus"
)

func StartStatusReporter(ctx context.Context, scan_id string, scanner *scan.Scanner) chan error {

	res := make(chan error)
	startScanJob()

	//If we don't get any active status back within threshold,
	//we consider the scan job as dead
	threshold := *scanner.InactiveThreshold

	go func() {
		defer stopScanJob()
		ticker := time.NewTicker(1 * time.Second)
		var err error
		ts := time.Now()
		log.Infof("StatusReporter started, scan_id: %s", scan_id)
	loop:
		for {
			select {
			case err = <-res:
				break loop
			case <-ctx.Done():
				err = ctx.Err()
				break loop
			case <-scanner.ScanStatusChan:
				ts = time.Now()
			case <-ticker.C:
				if scanner.Stopped.Load() == true {
					log.Errorf("Scanner job stopped, scan_id: %s", scan_id)
					break loop
				}

				elapsed := int(time.Since(ts).Seconds())
				if elapsed > threshold {
					err = fmt.Errorf("Scan job aborted due to inactivity")
					log.Errorf("Scanner job aborted due to inactivity, scan_id: %s" + scan_id)
					scanner.Aborted.Store(true)
					break loop
				} else {
					output.WriteScanStatus("IN_PROGRESS", scan_id, "")
				}
			}
		}

		if scanner.Stopped.Load() == true {
			output.WriteScanStatus("ERROR", scan_id, "Scan stopped by user")
		} else if err != nil {
			output.WriteScanStatus("ERROR", scan_id, err.Error())
		} else {
			output.WriteScanStatus("COMPLETE", scan_id, "")
		}

		log.Infof("StatusReporter finished, scan_id: %s", scan_id)
	}()
	return res
}
