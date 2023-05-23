package yararules

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

// NOTE:::Do not expose the rules
// Instead add a wrapper here protected with mutex
type YaraRules struct {
	RulesPath string
	rules     *yara.Rules
	ruleMutex sync.Mutex
}

func New(rulePath string) *YaraRules {
	return &YaraRules{RulesPath: rulePath}
}

// Not thread safe function.Must only be called during the init.
func (yr *YaraRules) Compile(purpose int, failOnCompileWarning bool) error {
	var c *yara.Compiler

	var err error
	if c, err = yara.NewCompiler(); err != nil {
		return err
	}

	for k, v := range extvars[purpose] {
		if err = c.DefineVariable(k, v); err != nil {
			return err
		}
	}

	paths, err := getRuleFiles(yr.RulesPath)
	if err != nil {
		log.Error(err)
		return err
	}

	if len(paths) == 0 {
		return errors.New("no Yara rule files found")
	}

	for _, path := range paths {
		// We use the include callback function to actually read files
		// because yr_compiler_add_string() does not accept a file
		// name.
		log.Infof("including yara rule file %s", path)
		if err = c.AddString(fmt.Sprintf(`include "%s"`, path), ""); err != nil {
			log.Errorf("error obtained %s", err)
			return err
		}
	}

	purposeStr := [...]string{"file", "process"}[purpose]
	yr.rules, err = c.GetRules()
	if err != nil {
		for _, e := range c.Errors {
			log.Errorf("YARA compiler error in %s ruleset: %s:%d %s",
				purposeStr, e.Filename, e.Line, e.Text)
		}
		return fmt.Errorf("%d YARA compiler errors(s) found, rejecting %s ruleset",
			len(c.Errors), purposeStr)
	}

	if len(c.Warnings) > 0 {
		for _, w := range c.Warnings {
			log.Warn("YARA compiler warning in %s ruleset: %s:%d %s",
				purposeStr, w.Filename, w.Line, w.Text)
		}
		if failOnCompileWarning {
			return fmt.Errorf("%d YARA compiler warning(s) found, rejecting %s ruleset",
				len(c.Warnings), purposeStr)
		}
	}

	if len(yr.rules.GetRules()) == 0 {
		return errors.New("No YARA rules defined")
	}
	return nil
}

func (yr *YaraRules) NewScanner() (*yara.Scanner, error) {

	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()

	scanner, err := yara.NewScanner(yr.rules)
	if err != nil {
		return nil, err
	}
	scanner.SetTimeout(1 * time.Minute)
	scanner.SetFlags(0)
	return scanner, nil
}

func (yr *YaraRules) DefineVariable(name string, value any) error {
	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()

	return yr.rules.DefineVariable(name, value)
}

func (yr *YaraRules) ScanFileDescriptor(fd uintptr, flags yara.ScanFlags,
	timeout time.Duration, cb yara.ScanCallback) error {

	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()

	return yr.rules.ScanFileDescriptor(fd, flags, timeout, cb)
}

func (yr *YaraRules) ScanMem(buf []byte, flags yara.ScanFlags,
	timeout time.Duration, cb yara.ScanCallback) error {

	yr.ruleMutex.Lock()
	defer yr.ruleMutex.Unlock()

	return yr.rules.ScanMem(buf, flags, timeout, cb)
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
