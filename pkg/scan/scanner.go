package scan

import (
	"github.com/deepfence/YaraHunter/pkg/config"
	yara "github.com/hillu/go-yara/v4"
)

func New(opts *config.Options, yaraconfig *config.Config, yr *yara.Rules) (*Scanner, error) {
	return &Scanner{opts, yaraconfig, yr}, nil
}

type Scanner struct {
	*config.Options
	*config.Config
	Rules *yara.Rules
}

func (s *Scanner) SetImageName(imageName string) {
	s.ImageName = &imageName
}
