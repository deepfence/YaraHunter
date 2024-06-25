package runner

import (
	"github.com/deepfence/YaraHunter/pkg/output"
	log "github.com/sirupsen/logrus"
)

func removeDuplicateIOCs(iocs []output.IOCFound) []output.IOCFound {
	keys := make(map[string]bool)
	list := []output.IOCFound{}
	for _, entry := range iocs {
		uniqueKey := entry.CompleteFilename + entry.RuleName + entry.Class + entry.LayerID
		if _, value := keys[uniqueKey]; !value {
			keys[uniqueKey] = true
			list = append(list, entry)
		} else {
			log.Infof("Duplicate IOC found: %s", entry.CompleteFilename)
		}
	}
	return list
}
