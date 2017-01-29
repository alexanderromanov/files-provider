package files

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"

	"github.com/alexanderromanov/files-provider/domains"
)

// AzureStorageCredentials contains credentials for Azure storage account
type AzureStorageCredentials struct {
	Name string
	Key  string
}

// Provider returns file content
type Provider interface {
	GetFileContent(website *domains.WebsiteInfo, path string) (io.ReadCloser, error)
}

type provider struct {
	fileServices map[string]fileServiceClient
}

// ErrInternalServerError is generic error when provider cannot get file from storage
var ErrInternalServerError = errors.New("cannot get file due to some internal error")

// NewProvider returns instance of Provider
func NewProvider(credentials []AzureStorageCredentials) (Provider, error) {
	fileServices := make(map[string]fileServiceClient)
	for _, c := range credentials {
		client, err := newBasicClient(c.Name, c.Key)
		if err != nil {
			return nil, fmt.Errorf("cannot create file service client for share %s: %v", c.Name, err)
		}
		fileService := client.newFileService()
		fileServices[c.Name] = fileService
	}

	return &provider{fileServices: fileServices}, nil
}

// GetFileContent returns io.ReadCloser for file with given path
func (p *provider) GetFileContent(website *domains.WebsiteInfo, path string) (io.ReadCloser, error) {
	client, ok := p.fileServices[website.Share.StorageAccount]
	if !ok {
		log.Println("cannot get file service client for account " + website.Share.StorageAccount)
		return nil, ErrInternalServerError
	}

	actualPath := buildActualPath(website, path)

	result, err := client.getFileContent(actualPath)
	if err != nil {
		if err == ErrFileNotFound {
			return nil, ErrFileNotFound
		}
		log.Println(err)
		return nil, ErrInternalServerError
	}

	return result, nil
}

func buildActualPath(website *domains.WebsiteInfo, path string) string {
	sharePath := ""
	current := website.ID
	for current > 0 {
		section := current % 100
		current = current / 100
		sharePath = fmt.Sprintf("/%02d%s", section, sharePath)
	}

	result := "/" + website.Share.ShareName + sharePath
	unescapedPath, err := url.QueryUnescape(path)
	if err != nil {
		unescapedPath = path
	}

	return result + unescapedPath
}
