package scan

import (
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/hillu/go-yara/v4"
)

func New(opts *config.Options, yaraconfig *config.Config,
	yaraScannerIn *yara.Scanner, scanID string) *Scanner {

	statusChan := make(chan bool)
	return &Scanner{opts, yaraconfig, yaraScannerIn, scanID, statusChan, false, true}
}

type Scanner struct {
	*config.Options
	*config.Config

	YaraScanner    *yara.Scanner
	ScanID         string
	ScanStatusChan chan bool
	Aborted        bool
	ReportStatus   bool
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}
