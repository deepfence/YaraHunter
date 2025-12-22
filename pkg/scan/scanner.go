package scan

import (
	"fmt"
	"os"
	"sync"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/deepfence/match-scanner/pkg/extractor"
	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog/log"

	genscan "github.com/deepfence/match-scanner/pkg/scanner"
)

func New(
	hostMountPath string,
	extractorConfig cfg.Config,
	yaraScannerIn *yara.Scanner,
	scanID string) *Scanner {

	obj := Scanner{
		YaraScanner:   yaraScannerIn,
		ScanID:        scanID,
		Filters:       cfg.Config2Filter(extractorConfig),
		hostMountPath: hostMountPath,
	}
	return &obj
}

type Scanner struct {
	hostMountPath string
	YaraScanner   *yara.Scanner
	ScanID        string

	Filters cfg.Filters
}

type ScanType int

const (
	DirScan ScanType = iota
	ImageScan
	ContainerScan
	TarScan
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DirScan:
		return "host"
	case ImageScan:
		return "image"
	case ContainerScan:
		return "container"
	case TarScan:
		return "tar"
	}
	return ""
}

func IsExecAll(mode os.FileMode) bool {
	return mode&0111 == 0111
}

func (s *Scanner) Scan(ctx *tasks.ScanContext, stype ScanType, namespace, id string, scanID string, outputFn func(output.IOCFound, string)) error {
	var (
		extract extractor.FileExtractor
		err     error
		wg      sync.WaitGroup
	)
	switch stype {
	case DirScan:
		extract, err = extractor.NewDirectoryExtractor(s.Filters, id, true)
	case ImageScan:
		extract, err = extractor.NewImageExtractor(s.Filters, namespace, id)
	case ContainerScan:
		extract, err = extractor.NewContainerExtractor(s.Filters, namespace, id)
	case TarScan:
		extract, err = extractor.NewTarExtractor(s.Filters, namespace, id)
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	// results has to be 1 element max
	// to avoid overwriting the buffer entries
	results := make(chan []output.IOCFound)

	m := [2][]output.IOCFound{}
	i := 0

	wg.Add(1)
	go func() {
		defer wg.Done()
		for malwares := range results {
			for _, malware := range malwares {
				outputFn(malware, scanID)
			}
		}
	}()

	genscan.ApplyScan(ctx.Context, extract, func(f extractor.ExtractedFile) {
		if ctx != nil {
			err := ctx.Checkpoint("scan_phase")
			if err != nil {
				return
			}
		}

		if s.Filters.SkipNonExecutable && !IsExecAll(f.FilePermissions) {
			log.Debug().Str("file", f.Filename).Msg("Skipping non-executable file")
			return
		}

		err = ScanFile(s, f.Filename, f.Content, f.ContentSize, &m[i], "")
		if err != nil {
			log.Warn().Err(err).Str("file", f.Filename).Msg("scan file error")
		}

		results <- m[i]
		i += 1
		i %= len(m)
	})

	close(results)
	wg.Wait()
	return nil
}
