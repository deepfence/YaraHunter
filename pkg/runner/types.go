package runner

import (
	"sync"
	"time"
)

type IOCWriter interface {
	WriteJson() error
	WriteTable() error
}

type YaraRuleUpdater struct {
	yaraRuleListingJson  YaraRuleListing
	yaraRulePath         string
	downloadYaraRulePath string
	currentFileChecksum  string
	currentFilePath      string
	sync.RWMutex
}

// todo: move this to listing package
type YaraRuleListing struct {
	Available YaraRuleListingV3 `json:"available"`
}

type YaraRuleDetail struct {
	Built    time.Time `json:"built"`
	Version  int       `json:"version"`
	URL      string    `json:"url"`
	Checksum string    `json:"checksum"`
}

type YaraRuleListingV3 struct {
	V3 []YaraRuleDetail `json:"3"`
}
