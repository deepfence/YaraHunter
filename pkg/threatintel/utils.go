package threatintel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/VirusTotal/gyp"
	"github.com/rs/zerolog/log"
)

// RulesURL returns the URL for downloading malware rules for the given version
func RulesURL(version string) string {
	return fmt.Sprintf("https://threat-intel.threatmapper.org/threat-intel/malware/malware_%s.tar.gz", version)
}

// SecretRulesURL returns the URL for downloading secret rules for the given version
func SecretRulesURL(version string) string {
	return fmt.Sprintf("https://threat-intel.threatmapper.org/threat-intel/secret/secret_%s.tar.gz", version)
}

// VulnerabilityRulesURL returns the URL for downloading vulnerability db for the given version
func VulnerabilityRulesURL(version string) string {
	return fmt.Sprintf("https://threat-intel.threatmapper.org/threat-intel/vulnerability/vulnerability_%s.tar.gz", version)
}

func ExportYaraRules(outFile string, rules []DeepfenceRule, extra []string) error {
	file, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("file", outFile).Msg("failed to open file, skipping")
		return err
	}
	defer file.Close()

	for i := range extra {
		file.WriteString(fmt.Sprintf("import \"%s\"\n", extra[i]))
	}

	for _, rule := range rules {
		decoded, err := base64.StdEncoding.DecodeString(rule.Payload)
		if err != nil {
			log.Error().Err(err).Msg("err on base64 decode")
			continue
		}
		rs, err := gyp.ParseString(string(decoded))
		if err != nil {
			log.Error().Err(err).Msg("err on parse")
			continue
		}
		for _, r := range rs.Rules {
			r.WriteSource(file)
		}
	}

	return nil
}

func DownloadFile(ctx context.Context, url string) (*bytes.Buffer, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := http.Client{Timeout: 600 * time.Second, Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	var out bytes.Buffer
	_, err = io.Copy(bufio.NewWriter(&out), resp.Body)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func ProcessTarGz(content []byte, sourceFile string, outPath string,
	processFile func(header *tar.Header, reader io.Reader, outPath string) error) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar file: %w", err)
		}

		if header.FileInfo().IsDir() {
			continue
		}

		if !strings.Contains(header.Name, sourceFile) {
			continue
		}

		if err := processFile(header, tarReader, outPath); err != nil {
			return fmt.Errorf("failed to process file %s: %w", header.Name, err)
		}
	}

	return nil
}
