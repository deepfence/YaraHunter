package jobs

import (
	"context"
	"time"

	"github.com/deepfence/YaraHunter/pkg/output"
)

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
				output.WriteScanStatus("IN_PROGRESS", scan_id, "")
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
