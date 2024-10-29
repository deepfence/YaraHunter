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
	log "github.com/sirupsen/logrus"
)

func ExportYaraRules(outFile string, rules []DeepfenceRule, extra []string) error {

	file, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.ModePerm)
	if err != nil {
		log.Errorf("failed to open file: %s, skipping", err)
		return err
	}
	defer file.Close()

	for i := range extra {
		file.WriteString(fmt.Sprintf("import \"%s\"\n", extra[i]))
	}

	for _, rule := range rules {
		decoded, err := base64.StdEncoding.DecodeString(rule.Payload)
		if err != nil {
			log.Errorf("err on base64 decode: %v", err)
			continue
		}
		rs, err := gyp.ParseString(string(decoded))
		if err != nil {
			log.Errorf("err on parse: %v", err)
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
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := http.Client{Timeout: 600 * time.Second}

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
	// Uncompress the gzipped content
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	// Create a tar reader to read the uncompressed data
	tarReader := tar.NewReader(gzipReader)

	// Iterate over the files in the tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tar archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar file: %w", err)
		}

		// skip some files
		if header.FileInfo().IsDir() {
			continue
		}

		if !strings.Contains(header.Name, sourceFile) {
			continue
		}

		// Run the provided callback function on the current file
		if err := processFile(header, tarReader, outPath); err != nil {
			return fmt.Errorf("failed to process file %s: %w", header.Name, err)
		}
	}

	return nil
}

func SkipRulesUpdate(checksumFilePath, checksum string) bool {
	sum, err := os.ReadFile(checksumFilePath)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	if string(sum) == checksum {
		return true
	}

	return false
}
