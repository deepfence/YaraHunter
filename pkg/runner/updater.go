package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/deepfence/YaraHunter/pkg/config"
	utils "github.com/deepfence/YaraHunter/utils"
	log "github.com/sirupsen/logrus"
)

func ScheduleYaraHunterUpdater(opts *config.Options, newwg *sync.WaitGroup) {
	defer newwg.Done()
	if *opts.SocketPath != "" {
		// fmt.Println("Go Tickers Tutorial")
		// this creates a new ticker which will
		// `tick` every 1 second.
		ticker := time.NewTicker(10 * time.Hour)

		// for every `tick` that our `ticker`
		// emits, we print `tock`
		for t := range ticker.C {
			fmt.Println("Invoked at ", t)
			err := StartYaraHunterUpdater(*opts.RulesPath, *opts.ConfigPath, *opts.RulesListingURL)
			if err != nil {
				log.Panicf("main: failed to serve: %v", err)
			}
		}
	}
}

func StartYaraHunterUpdater(rulesPath, configPath, rulesListingURL string) error {
	yaraRuleUpdater, err := NewYaraRuleUpdater(rulesPath)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	_, err = utils.DownloadFile(rulesListingURL, configPath)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	content, err := os.ReadFile(filepath.Join(configPath, "/listing.json"))
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	var yaraRuleListingJSON YaraRuleListing
	err = json.Unmarshal(content, &yaraRuleListingJSON)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	if len(yaraRuleListingJSON.Available.V3) > 0 {
		if yaraRuleListingJSON.Available.V3[0].Checksum != yaraRuleUpdater.currentFileChecksum {
			yaraRuleUpdater.currentFileChecksum = yaraRuleListingJSON.Available.V3[0].Checksum
			file, err := json.MarshalIndent(yaraRuleUpdater, "", " ")
			if err != nil {
				log.Errorf("main: failed to marshal: %v", err)
				return err
			}
			err = os.WriteFile(path.Join(rulesPath, "metaListingData.json"), file, 0644)
			if err != nil {
				log.Errorf("main: failed to write to metaListingData.json: %v", err)
				return err
			}
			fileName, err := utils.DownloadFile(yaraRuleListingJSON.Available.V3[0].URL, configPath)
			if err != nil {
				log.Errorf("main: failed to download file: %v", err)
				return err
			}

			if utils.PathExists(filepath.Join(configPath, fileName)) {
				log.Infof("rule file exists: %s", filepath.Join(configPath, fileName))

				readFile, readErr := os.OpenFile(filepath.Join(configPath, fileName), os.O_CREATE|os.O_RDWR, 0755)
				if readErr != nil {
					log.Errorf("main: failed to open rules tar file : %v", readErr)
					return readErr
				}

				defer readFile.Close()

				newFile, err := utils.CreateFile(configPath, "malware.yar")
				if err != nil {
					log.Errorf("main: failed to create malware.yar: %v", err)
					return err
				}

				defer newFile.Close()

				err = utils.Untar(newFile, readFile)
				if err != nil {
					log.Errorf("main: failed to untar: %v", err)
					return err
				}
			}
		}
	}
	return nil
}

func NewYaraRuleUpdater(rulesPath string) (*YaraRuleUpdater, error) {
	updater := &YaraRuleUpdater{
		yaraRuleListingJSON:  YaraRuleListing{},
		yaraRulePath:         path.Join(rulesPath, "metaListingData.json"),
		downloadYaraRulePath: "",
	}
	if utils.PathExists(updater.yaraRulePath) {
		content, err := os.ReadFile(updater.yaraRulePath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(content, &updater)
		if err != nil {
			return nil, err
		}
	}
	return updater, nil
}
