package scan

import (
	"sync/atomic"

	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/hillu/go-yara/v4"
)

func New(opts *config.Options, yaraconfig *config.Config,
	yaraScannerIn *yara.Scanner, scanID string) *Scanner {

	statusChan := make(chan bool)
	obj := Scanner{opts, yaraconfig, yaraScannerIn, scanID, statusChan,
		atomic.Bool{}, atomic.Bool{}}
	obj.Aborted.Store(false)
	obj.ReportStatus.Store(true)
	return &obj
}

type Scanner struct {
	*config.Options
	*config.Config

	YaraScanner    *yara.Scanner
	ScanID         string
	ScanStatusChan chan bool
	Aborted        atomic.Bool
	ReportStatus   atomic.Bool
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}
