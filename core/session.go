package core

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
)

type Session struct {
	sync.Mutex
	Version   string
	Options   *Options
	Config    *Config
	Context   context.Context
	Log       *Logger
	YaraRules *yara.Rules
}

var (
	session     *Session
	sessionSync sync.Once
	err         error
)

func (s *Session) Start() {
	rand.Seed(time.Now().Unix())

	s.InitLogger()
	s.InitThreads()
}

func (s *Session) InitLogger() {
	s.Log = &Logger{}
	s.Log.SetLogLevel(*s.Options.DebugLevel)
}

func (s *Session) InitThreads() {
	if *s.Options.Threads == 0 {
		numCPUs := runtime.NumCPU()
		s.Options.Threads = &numCPUs
	}

	runtime.GOMAXPROCS(*s.Options.Threads + 1)
}

func GetSession() *Session {
	sessionSync.Do(func() {
		session = &Session{
			Context: context.Background(),
		}

		if session.Options, err = ParseOptions(); err != nil {
			fmt.Println(err)
			session.Log.Error(err.Error())
			os.Exit(1)
		}

		if session.Config, err = ParseConfig(session.Options); err != nil {
			session.Log.Error(err.Error())
			os.Exit(1)
		}

		pathSeparator := string(os.PathSeparator)
		var excludedPaths []string
		for _, excludedPath := range session.Config.ExcludedPaths {
			excludedPaths = append(excludedPaths, strings.Replace(excludedPath, "{sep}", pathSeparator, -1))
		}
		session.Config.ExcludedPaths = excludedPaths

		session.Start()

		rules, err := compile(filescan, session)
		if err != nil {
			session.Log.Error("compiling rules issue: %s", err)
			os.Exit(1)
		}
		session.YaraRules = rules
	})

	return session
}
