package scan

import (
	"github.com/deepfence/YaraHunter/pkg/config"
	// y "github.com/deepfence/YaraHunter/pkg/yara"
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

/*
type Options struct {
    Threads              *int
    DebugLevel           *string
    MaximumFileSize      *int64
    TempDirectory        *string
    Local                *string
    HostMountPath        *string
    ConfigPath           *string
    OutputPath           *string
    JsonFilename         *string
    ImageName            *string
    MaxIOC               *uint
    ContainerId          *string
    ContainerNS          *string
    SocketPath           *string
    HttpPort             *string
    StandAloneHttpPort   *string
    RulesPath            *string
    FailOnCompileWarning *bool
}
*/
