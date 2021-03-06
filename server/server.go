package server

import (
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/alexanderromanov/files-provider/domains"
	"github.com/alexanderromanov/files-provider/files"
)

// NewServer returns instance of file server
func NewServer(filesProvider files.Provider, resolver domains.Resolver, prefix string) (http.Handler, error) {
	if prefix == "" {
		return nil, errors.New("prefix should not be empty")
	}

	return &fileServer{filesProvider, resolver, prefix}, nil
}

type fileServer struct {
	filesProvider files.Provider
	resolver      domains.Resolver
	prefix        string
}

func (server *fileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	if !strings.HasPrefix(path, server.prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	host := r.Host
	// Slice off any port information.
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}

	websiteInfo, domainFound := server.resolver.Resolve(host)
	if !domainFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if websiteInfo.IsBlocked {
		// 402 - Payment Required
		w.WriteHeader(402)
		return
	}

	file, err := server.filesProvider.GetFileContent(websiteInfo, path)
	if file != nil {
		defer file.Close()
	}
	if err != nil {
		if err == files.ErrFileNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("cannot get file for %s: %v\n", path, err)
		return
	}

	extension := filepath.Ext(path)
	mimeType := mime.TypeByExtension(extension)

	w.Header().Set("Content-Type", mimeType)

	written, err := io.Copy(w, file)
	if err != nil {
		// broken pipe errors are pretty common and are not errors in a sense where
		// we can fix anything, so it's better to filter them out from logs
		if !strings.HasSuffix(err.Error(), "broken pipe") {
			log.Printf("error while copying: %v\n", err)
		}

		// if any number of byte were written to response 200 status is automatically set
		// calling WriteHeader would cause http error
		if written == 0 {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
}
