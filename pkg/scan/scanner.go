package scan

import (
	"github.com/deepfence/YaraHunter/pkg/config"
	"github.com/hillu/go-yara/v4"
)

func New(opts *config.Options, yaraconfig *config.Config, yaraScannerIn *yara.Scanner) *Scanner {
	return &Scanner{opts, yaraconfig, yaraScannerIn}
}

type Scanner struct {
	*config.Options
	*config.Config
	YaraScanner *yara.Scanner
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}
