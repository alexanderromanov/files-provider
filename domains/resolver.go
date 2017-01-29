package domains

import (
	"errors"
	"fmt"
	"io"
	"log"
	"time"
)

// Resolver allows to get meta information about website based on based on domain name
type Resolver interface {
	io.Closer
	Resolve(domain string) (*WebsiteInfo, bool)
}

// Resolver allows to get information about website from its domain
type resolver struct {
	settings      WebsiteLoaderSettings
	shareSettings FileShareSettings
	websites      map[string]*WebsiteInfo
	queue         chan resolveTask
	closing       chan bool
}

type resolveTask struct {
	domain string
	result chan resolveResult
}

type resolveResult struct {
	website *WebsiteInfo
	found   bool
}

const (
	reloadInterval = 10
)

// NewResolver creates new Resolver
func NewResolver(settings WebsiteLoaderSettings, shareSettings FileShareSettings) (Resolver, error) {
	if err := settings.validate(); err != nil {
		return nil, fmt.Errorf("resolver settings are not valid: %v", err)
	}

	if shareSettings == nil {
		return nil, errors.New("share settings are not provided")
	}

	r := &resolver{
		settings:      settings,
		shareSettings: shareSettings,
		closing:       make(chan bool, 1),
		queue:         make(chan resolveTask, 20),
	}
	websites, err := loadWebsites(settings, shareSettings)
	if err != nil {
		return nil, fmt.Errorf("cannot load domain information: %v", err)
	}
	r.websites = websites

	go r.run()

	return r, nil
}

// Resolve looks up for domain in resolver registry and returns information about it
func (r *resolver) Resolve(domain string) (*WebsiteInfo, bool) {
	c := make(chan resolveResult)
	r.queue <- resolveTask{domain: domain, result: c}

	result := <-c
	return result.website, result.found
}

// Close initiates tear down of Resolver
func (r *resolver) Close() error {
	r.closing <- true
	return nil
}

func (r *resolver) run() {
	newWebsites := make(chan map[string]*WebsiteInfo, 1)
	ticker := time.NewTicker(reloadInterval * time.Minute)

	for {
		select {
		case <-ticker.C:
			go func() {
				websites, err := loadWebsites(r.settings, r.shareSettings)
				if err != nil {
					log.Printf("fail to reload website infos: %v", err)
					return
				}
				newWebsites <- websites
			}()
		case websites := <-newWebsites:
			r.websites = websites
		case task := <-r.queue:
			go func() {
				website, ok := r.websites[task.domain]
				task.result <- resolveResult{website: website, found: ok}
			}()
		case <-r.closing:
			ticker.Stop()
			close(newWebsites)
			close(r.queue)
			return
		}
	}
}
