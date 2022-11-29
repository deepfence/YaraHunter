package core

import (
	"errors"
	"fmt"
	yr "github.com/hillu/go-yara/v4"
	"io/ioutil"
	"path/filepath"
	"strings"
)

const filescan = 0
const procscan = 1

var extvars = map[int]map[string]interface{}{
	filescan: {
		"filename":  "",
		"filepath":  "",
		"extension": "",
		"filetype":  "",
	},
	procscan: {
		"pid":        -1,
		"executable": "",
	},
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

func compile(purpose int, session *Session) (*yr.Rules, error) {
	var c *yr.Compiler
	session.Log.Info("including yara rule file ")

	var err error
	if c, err = yr.NewCompiler(); err != nil {
		return nil, err
	}

	session.Log.Info("including yara rule file ")

	for k, v := range extvars[purpose] {
		if err = c.DefineVariable(k, v); err != nil {
			return nil, err
		}
	}

	session.Log.Info("including yara rule file ")
	session.Log.Info("including yara rule file ")

	paths, err := getRuleFiles(*session.Options.RulesPath)
	session.Log.Error("including yara rule file %s", err)
	if len(paths) == 0 {
		return nil, errors.New("no Yara rule files found")
	}
	for _, path := range paths {
		// We use the include callback function to actually read files
		// because yr_compiler_add_string() does not accept a file
		// name.
		session.Log.Info("including yara rule file %s", path)
		if err = c.AddString(fmt.Sprintf(`include "%s"`, path), ""); err != nil {
			session.Log.Error("error obtained %s", err)
			return nil, err
		}
	}
	purposeStr := [...]string{"file", "process"}[purpose]
	rs, err := c.GetRules()
	if err != nil {
		for _, e := range c.Errors {
			session.Log.Error("YARA compiler error in %s ruleset: %s:%d %s",
				purposeStr, e.Filename, e.Line, e.Text)
		}
		return nil, fmt.Errorf("%d YARA compiler errors(s) found, rejecting %s ruleset",
			len(c.Errors), purposeStr)
	}
	if len(c.Warnings) > 0 {
		for _, w := range c.Warnings {
			session.Log.Warn("YARA compiler warning in %s ruleset: %s:%d %s",
				purposeStr, w.Filename, w.Line, w.Text)
		}
		if *session.Options.FailOnCompileWarning == true {
			return nil, fmt.Errorf("%d YARA compiler warning(s) found, rejecting %s ruleset",
				len(c.Warnings), purposeStr)
		}
	}
	if len(rs.GetRules()) == 0 {
		return nil, errors.New("No YARA rules defined")
	}
	session.Log.Info("number of rules", len(rs.GetRules()))
	return rs, nil
}
