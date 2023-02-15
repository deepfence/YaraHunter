package yararules

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	// "github.com/aws/aws-sdk-go/aws/session"
	"github.com/deepfence/YaraHunter/constants"
	yara "github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"
)

var extvars = map[int]map[string]interface{}{
	constants.Filescan: {
		"filename":  "",
		"filepath":  "",
		"extension": "",
		"filetype":  "",
	},
	constants.Procscan: {
		"pid":        -1,
		"executable": "",
	},
}

type YaraRules struct {
	RulesPath string
	YaraRules *yara.Rules
	ruleMutex sync.Mutex
}

func New(rulePath string) *YaraRules {
	return &YaraRules{RulesPath: rulePath}
}

func (yr *YaraRules) SetYaraRule(rules *yara.Rules) {
	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()
	yr.YaraRules = rules
}

func (yr *YaraRules) GetYaraRule() *yara.Rules {
	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()
	return yr.YaraRules
}

func (yr *YaraRules) Compile(purpose int, failOnCompileWarning bool) (*yara.Rules, error) {
	var c *yara.Compiler
	//log.Info("including yara rule file ")

	var err error
	if c, err = yara.NewCompiler(); err != nil {
		return nil, err
	}

	//log.Info("including yara rule file ")

	for k, v := range extvars[purpose] {
		if err = c.DefineVariable(k, v); err != nil {
			return nil, err
		}
	}

	//log.Info("including yara rule file ")
	//log.Info("including yara rule file ")

	paths, err := getRuleFiles(yr.RulesPath)
	if len(paths) == 0 {
		return nil, errors.New("no Yara rule files found")
	}
	for _, path := range paths {
		// We use the include callback function to actually read files
		// because yr_compiler_add_string() does not accept a file
		// name.
		log.Info("including yara rule file %s", path)
		if err = c.AddString(fmt.Sprintf(`include "%s"`, path), ""); err != nil {
			log.Error("error obtained %s", err)
			return nil, err
		}
	}
	purposeStr := [...]string{"file", "process"}[purpose]
	yr.YaraRules, err = c.GetRules()
	if err != nil {
		for _, e := range c.Errors {
			log.Error("YARA compiler error in %s ruleset: %s:%d %s",
				purposeStr, e.Filename, e.Line, e.Text)
		}
		return nil, fmt.Errorf("%d YARA compiler errors(s) found, rejecting %s ruleset",
			len(c.Errors), purposeStr)
	}
	if len(c.Warnings) > 0 {
		for _, w := range c.Warnings {
			log.Warn("YARA compiler warning in %s ruleset: %s:%d %s",
				purposeStr, w.Filename, w.Line, w.Text)
		}
		if failOnCompileWarning {
			return nil, fmt.Errorf("%d YARA compiler warning(s) found, rejecting %s ruleset",
				len(c.Warnings), purposeStr)
		}
	}
	if len(yr.YaraRules.GetRules()) == 0 {
		return nil, errors.New("No YARA rules defined")
	}
	return yr.YaraRules, nil
}

func getRuleFiles(rulesPath string) ([]string, error) {
	var fileNames []string
	files, err := ioutil.ReadDir(rulesPath)
	if err != nil {
		return fileNames, err
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".yar") || strings.HasSuffix(f.Name(), ".yara") {
			fileNames = append(fileNames, filepath.Join(rulesPath, f.Name()))
		}
	}
	return fileNames, nil
}
