package runner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	if *opts.SocketPath != "" && *opts.HttpPort != "" {
		// fmt.Println("Go Tickers Tutorial")
		// this creates a new ticker which will
		// `tick` every 1 second.
		ticker := time.NewTicker(10 * time.Hour)

		// for every `tick` that our `ticker`
		// emits, we print `tock`
		for t := range ticker.C {
			fmt.Println("Invoked at ", t)
			err := StartYaraHunterUpdater(*opts.RulesPath, *opts.ConfigPath, *opts.RulesListingUrl)
			if err != nil {
				log.Fatal("main: failed to serve: %v", err)
			}
		}
	}
}

func StartYaraHunterUpdater(rulesPath, configPath, rulesListingUrl string) error {
	err, yaraRuleUpdater := NewYaraRuleUpdater(rulesPath)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	_, err = utils.DownloadFile(rulesListingUrl, configPath)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	content, err := ioutil.ReadFile(filepath.Join(configPath, "/listing.json"))
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	var yaraRuleListingJson YaraRuleListing
	err = json.Unmarshal(content, &yaraRuleListingJson)
	if err != nil {
		log.Errorf("main: failed to serve: %v", err)
		return err
	}
	if len(yaraRuleListingJson.Available.V3) > 0 {
		if yaraRuleListingJson.Available.V3[0].Checksum != yaraRuleUpdater.currentFileChecksum {
			yaraRuleUpdater.currentFileChecksum = yaraRuleListingJson.Available.V3[0].Checksum
			file, err := json.MarshalIndent(yaraRuleUpdater, "", " ")
			if err != nil {
				log.Errorf("main: failed to serve: %v", err)
				return err
			}
			err = ioutil.WriteFile(path.Join(rulesPath, "metaListingData.json"), file, 0644)
			if err != nil {
				log.Errorf("main: failed to serve: %v", err)
				return err
			}
			fileName, err := utils.DownloadFile(yaraRuleListingJson.Available.V3[0].URL, configPath)
			if err != nil {
				log.Errorf("main: failed to serve: %v", err)
				return err
			}

			if utils.PathExists(filepath.Join(configPath, fileName)) {
				log.Infof("rule file exists: %s", filepath.Join(configPath, fileName))

				readFile, readErr := os.OpenFile(filepath.Join(configPath, fileName), os.O_CREATE|os.O_RDWR, 0755)
				if readErr != nil {
					log.Errorf("main: failed to serve: %v", readErr)
					return readErr
				}

				defer readFile.Close()

				newFile, err := utils.CreateFile(configPath, "malware.yar")
				if err != nil {
					log.Errorf("main: failed to create: %v", err)
					return err
				}

				defer newFile.Close()

				err = utils.Untar(newFile, readFile)
				if err != nil {
					log.Errorf("main: failed to serve: %v", err)
					return err
				}
			}
		}
	}
	return nil
}

func NewYaraRuleUpdater(rulesPath string) (error, *YaraRuleUpdater) {
	updater := &YaraRuleUpdater{
		yaraRuleListingJson:  YaraRuleListing{},
		yaraRulePath:         path.Join(rulesPath, "metaListingData.json"),
		downloadYaraRulePath: "",
	}
	if utils.PathExists(updater.yaraRulePath) {
		content, err := ioutil.ReadFile(updater.yaraRulePath)
		if err != nil {
			return err, nil
		}
		err = json.Unmarshal(content, &updater)
		if err != nil {
			return err, nil
		}
	}
	return nil, updater
}
