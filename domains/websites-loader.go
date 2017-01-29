package domains

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// WebsiteLoaderSettings contains settings required to connect to DomainInfo provider
type WebsiteLoaderSettings struct {
	URL                 string
	Token               string
	ServiceDomainSuffix string
}

// WebsiteInfo provides basic information about website
type WebsiteInfo struct {
	ID        int
	Share     *FileShare
	IsBlocked bool
}

// FileShare contains information about Azure File Share
type FileShare struct {
	ShareName      string
	StorageAccount string
}

// FileShareSettings maps name of file share id to its details
type FileShareSettings map[string]*FileShare

func loadWebsites(settings WebsiteLoaderSettings, shareSettings FileShareSettings) (map[string]*WebsiteInfo, error) {
	req, err := http.NewRequest("GET", settings.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("error when forming request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "OAuth "+settings.Token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("error when calling %s: %v", settings.URL, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP response error %d", resp.StatusCode)
	}

	var domains []websiteInfoJSON
	err = json.NewDecoder(resp.Body).Decode(&domains)
	if err != nil {
		return nil, fmt.Errorf("fail to decode json response: %v", err)
	}

	result := map[string]*WebsiteInfo{}
	for _, info := range domains {
		domain, value := info.toWebsiteInfo(shareSettings)

		result[domain] = value

		if !strings.HasSuffix(domain, settings.ServiceDomainSuffix) {
			result["www."+domain] = value
		}
	}

	return result, nil
}

type domainsList struct {
	Domains []websiteInfoJSON `json:"domains"`
}

type websiteInfoJSON struct {
	Domain           string `json:"domain"`
	ID               int    `json:"websiteId"`
	FileserverPrefix string `json:"fileserverPrefix"`
	IsBlocked        bool   `json:"blocked"`
	IsTrial          bool   `json:"trial"`
}

func (w *websiteInfoJSON) toWebsiteInfo(shareSettings FileShareSettings) (domain string, websiteInfo *WebsiteInfo) {
	domain = strings.ToLower(w.Domain)
	websiteInfo = &WebsiteInfo{
		ID:        w.ID,
		Share:     shareSettings[w.FileserverPrefix],
		IsBlocked: w.IsBlocked,
	}

	return
}

func (settings *WebsiteLoaderSettings) validate() error {
	if settings.URL == "" {
		return errors.New("url is not provided")
	}

	if settings.Token == "" {
		return errors.New("token is not provided")
	}

	if settings.ServiceDomainSuffix == "" {
		return errors.New("service domain suffix is not provided")
	}

	return nil
}
