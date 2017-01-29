package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/alexanderromanov/files-provider/domains"
	"github.com/alexanderromanov/files-provider/files"
	"github.com/alexanderromanov/files-provider/server"
)

func main() {
	config, err := getConfig()
	if err != nil {
		log.Fatalf("cannot read config: %v", err)
	}

	filesProvider, err := newFilesProvider(config)
	if err != nil {
		log.Fatalf("cannot create filesProvider: %v", err)
	}

	domainsResolver, err := newDomainsResolver(config)
	if err != nil {
		log.Fatalf("cannot create domains resolver: %v", err)
	}
	defer domainsResolver.Close()

	handler, err := server.NewServer(filesProvider, domainsResolver, config.FileServerPrefix)
	if err != nil {
		log.Fatalf("cannot initialize file server: %v", err)
	}

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: handler,
	}

	log.Println("starting server")
	server.ListenAndServe()
}

func newDomainsResolver(config *appConfig) (domains.Resolver, error) {
	resolverSettings := domains.WebsiteLoaderSettings{
		ServiceDomainSuffix: config.ResolverSettings.ServiceDomainSuffix,
		Token:               config.ResolverSettings.Token,
		URL:                 config.ResolverSettings.URL,
	}

	shareSettings := make(map[string]*domains.FileShare)
	for id, share := range config.Shares {
		shareSettings[id] = &domains.FileShare{StorageAccount: share.StorageAccount, ShareName: share.FolderName}
	}

	return domains.NewResolver(resolverSettings, shareSettings)
}

func newFilesProvider(config *appConfig) (files.Provider, error) {
	azureCredentials := make([]files.AzureStorageCredentials, 0, len(config.Shares))
	shareSettings := make(map[string]*domains.FileShare)
	for id, share := range config.Shares {
		cred := files.AzureStorageCredentials{Name: share.StorageAccount, Key: share.StorageKey}
		azureCredentials = append(azureCredentials, cred)

		shareSettings[id] = &domains.FileShare{StorageAccount: share.StorageAccount, ShareName: share.FolderName}
	}

	return files.NewProvider(azureCredentials)
}
