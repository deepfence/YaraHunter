package scan

import (
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/hillu/go-yara/v4"
)

func New(opts *config.Options, yaraconfig *config.Config,
	yaraScannerIn *yara.Scanner, scanID string) *Scanner {

	obj := Scanner{opts, yaraconfig, yaraScannerIn, scanID}
	return &obj
}

type Scanner struct {
	*config.Options
	*config.Config

	YaraScanner *yara.Scanner
	ScanID      string
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}
