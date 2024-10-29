package threatintel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/deepfence/YaraHunter/utils"
	log "github.com/sirupsen/logrus"
)

var (
	threatIntelURL  = "https://threat-intel.deepfence.io/threat-intel/listing.json"
	threatIntelTest = utils.GetEnvOrDefault("DEEPFENCE_THREAT_INTEL_TEST", "false") == "true"
)

var ErrDatabaseNotFound = errors.New("database type not found")

func FetchThreatIntelListing(ctx context.Context, version, project, license string) (Listing, error) {

	var listing Listing

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	hc := http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, threatIntelURL, nil)
	if err != nil {
		log.Error("failed to construct new http request")
		return listing, err
	}

	req.Header.Set("x-license-key", license)

	q := req.URL.Query()
	q.Add("version", version)
	q.Add("product", project)
	if threatIntelTest {
		q.Add("test", "true")
	}
	req.URL.RawQuery = q.Encode()

	log.Debugf("query threatintel at %s", req.URL.String())

	resp, err := hc.Do(req)
	if err != nil {
		log.Error("failed http request")
		return listing, err
	}

	if resp.StatusCode != http.StatusOK {
		return listing, fmt.Errorf("%d invaid response code", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed read response body")
		return listing, err
	}
	defer resp.Body.Close()

	if err := json.Unmarshal(body, &listing); err != nil {
		log.Error("failed to decode response body")
		return listing, err
	}

	return listing, nil

}
