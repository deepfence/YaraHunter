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
		ticker := time.NewTicker(30 * time.Second)
		var err, abort error
		ts := time.Now()
	loop:
		for {
			select {
			case err = <-res:
				break loop
			case <-ctx.Done():
				abort = ctx.Err()
				break loop
			case <-scanner.ScanStatusChan:
				ts = time.Now()
			case <-ticker.C:
				elapsed := int(time.Since(ts).Seconds())
				if elapsed > threshold {
					err = fmt.Errorf("Scan job aborted due to inactivity")
					log.Error("Scanner job aborted as no update within threshold, Scan id:" + scan_id)
					scanner.Aborted.Store(true)
					break loop
				} else {
					output.WriteScanStatus("IN_PROGRESS", scan_id, "")
				}
			}
		}
		if abort != nil {
			output.WriteScanStatus("CANCELLED", scan_id, abort.Error())
			return
		}
		if err != nil {
			output.WriteScanStatus("ERROR", scan_id, err.Error())
			return
		}
		output.WriteScanStatus("COMPLETE", scan_id, "")
	}()
	return res
}
