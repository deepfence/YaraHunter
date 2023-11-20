package jobs

import "sync/atomic"

var (
	runningJobsNum atomic.Int32
)

func StartScanJob() {
	runningJobsNum.Add(1)
}

func StopScanJob() {
	runningJobsNum.Add(-1)
}

func GetRunningJobCount() int32 {
	return runningJobsNum.Load()
}
