package main

import "github.com/BurntSushi/toml"

type shareConfigRecord struct {
	StorageAccount string `toml:"storageAccount"`
	FolderName     string `toml:"folderName"`
	StorageKey     string `toml:"storageKey"`
}

type appConfig struct {
	Port             int                          `toml:"port"`
	FileServerPrefix string                       `toml:"fileServerPrefix"`
	ResolverSettings resolverSettings             `toml:"resolver"`
	Shares           map[string]shareConfigRecord `toml:"shares"`
}

type resolverSettings struct {
	URL                 string `toml:"url"`
	Token               string `toml:"token"`
	ServiceDomainSuffix string `toml:"serviceDomainSuffix"`
}

func getConfig() (*appConfig, error) {
	var config appConfig
	_, err := toml.DecodeFile("config.toml", &config)
	return &config, err
}
