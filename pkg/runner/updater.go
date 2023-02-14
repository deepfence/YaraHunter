package runner

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/deepfence/YaraHunter/core"
	utils "github.com/deepfence/YaraHunter/utils"
)

func ScheduleYaraHunterUpdater(newwg *sync.WaitGroup) {
	defer newwg.Done()
	if *session.Options.SocketPath != "" && *session.Options.HttpPort != "" {
		flag.Parse()
		fmt.Println("Go Tickers Tutorial")
		// this creates a new ticker which will
		// `tick` every 1 second.
		ticker := time.NewTicker(10 * time.Hour)

		// for every `tick` that our `ticker`
		// emits, we print `tock`
		for t := range ticker.C {
			fmt.Println("Invoked at ", t)
			err := StartYaraHunterUpdater()
			if err != nil {
				core.GetSession().Log.Fatal("main: failed to serve: %v", err)
			}
		}
	}
}

func StartYaraHunterUpdater() error {
	err, yaraRuleUpdater := NewYaraRuleUpdater()
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	_, err = utils.DownloadFile("https://threat-intel.deepfence.io/yara-rules/listing.json", *core.GetSession().Options.ConfigPath)
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	content, err := ioutil.ReadFile(filepath.Join(*core.GetSession().Options.ConfigPath, "/listing.json"))
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	var yaraRuleListingJson YaraRuleListing
	err = json.Unmarshal(content, &yaraRuleListingJson)
	if err != nil {
		core.GetSession().Log.Error("main: failed to serve: %v", err)
		return err
	}
	if len(yaraRuleListingJson.Available.V3) > 0 {
		if yaraRuleListingJson.Available.V3[0].Checksum != yaraRuleUpdater.currentFileChecksum {
			yaraRuleUpdater.currentFileChecksum = yaraRuleListingJson.Available.V3[0].Checksum
			file, err := json.MarshalIndent(yaraRuleUpdater, "", " ")
			if err != nil {
				core.GetSession().Log.Error("main: failed to serve: %v", err)
				return err
			}
			err = ioutil.WriteFile(path.Join(*core.GetSession().Options.RulesPath, "metaListingData.json"), file, 0644)
			if err != nil {
				core.GetSession().Log.Error("main: failed to serve: %v", err)
				return err
			}
			fileName, err := utils.DownloadFile(yaraRuleListingJson.Available.V3[0].URL, *core.GetSession().Options.ConfigPath)
			if err != nil {
				core.GetSession().Log.Error("main: failed to serve: %v", err)
				return err
			}

			if utils.PathExists(filepath.Join(*core.GetSession().Options.ConfigPath, fileName)) {
				fmt.Println("the file exists")

				readFile, readErr := os.OpenFile(filepath.Join(*core.GetSession().Options.ConfigPath, fileName), os.O_CREATE|os.O_RDWR, 0755)
				if readErr != nil {
					core.GetSession().Log.Error("main: failed to serve: %v", readErr)
					return readErr
				}
				newFile, err := utils.CreateFile(*core.GetSession().Options.ConfigPath, "malware.yar")
				if err != nil {
					core.GetSession().Log.Error("main: failed to create: %v", err)
					return err
				}
				err = utils.Untar(newFile, readFile)
				if err != nil {
					core.GetSession().Log.Error("main: failed to serve: %v", err)
					return err
				}
				session = core.GetSession()
				defer newFile.Close()
				defer readFile.Close()

			}

		}
	}
	return nil
}

func NewYaraRuleUpdater() (error, *YaraRuleUpdater) {
	updater := &YaraRuleUpdater{
		yaraRuleListingJson:  YaraRuleListing{},
		yaraRulePath:         path.Join(*core.GetSession().Options.RulesPath, "metaListingData.json"),
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
