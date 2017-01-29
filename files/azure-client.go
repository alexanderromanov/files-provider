package files

// most of the code here is taken from https://github.com/Azure/azure-sdk-for-go/

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// fileServiceClient contains operations for Microsoft Azure File Service.
type fileServiceClient struct {
	client client
}

// fileProperties contains various properties of a file returned from
// various endpoints like ListDirsAndFiles.
type fileProperties struct {
	CacheControl       string `header:"x-ms-cache-control"`
	ContentLength      uint64 `xml:"Content-Length"`
	ContentType        string `header:"x-ms-content-type"`
	CopyCompletionTime string
	CopyID             string
	CopySource         string
	CopyProgress       string
	CopyStatusDesc     string
	CopyStatus         string
	Disposition        string `header:"x-ms-content-disposition"`
	Encoding           string `header:"x-ms-content-encoding"`
	Etag               string
	Language           string `header:"x-ms-content-language"`
	LastModified       string
	MD5                string `header:"x-ms-content-md5"`
}

// FileStream contains file data returned from a call to GetFile.
type fileStream struct {
	Body       io.ReadCloser
	Properties *fileProperties
	Metadata   map[string]string
}

type compType string

const (
	compNone       compType = ""
	compList       compType = "list"
	compMetadata   compType = "metadata"
	compProperties compType = "properties"
	compRangeList  compType = "rangelist"
)

func (ct compType) String() string {
	return string(ct)
}

type resourceType string

const (
	resourceFile resourceType = ""
)

// ErrFileNotFound is returned when client requests file that doesn't exist
var ErrFileNotFound = errors.New("File Not Found")

func (rt resourceType) String() string {
	return string(rt)
}

// returns url.Values for the specified types
func getURLInitValues(comp compType, res resourceType) url.Values {
	values := url.Values{}
	if comp != compNone {
		values.Set("comp", comp.String())
	}
	if res != resourceFile {
		values.Set("restype", res.String())
	}
	return values
}

// getFile operation reads or downloads a file from the system, including its
// metadata and properties.
//
// See https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/get-file
func (f fileServiceClient) getFile(path string) (*fileStream, error) {
	resp, err := f.getResourceNoClose(path, compNone, resourceFile, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}

	if err = checkRespCode(resp.statusCode, []int{http.StatusOK, http.StatusPartialContent}); err != nil {
		resp.body.Close()
		return nil, err
	}

	props, err := getFileProps(resp.headers)
	if err != nil {
		return nil, err
	}

	md := getFileMDFromHeaders(resp.headers)
	return &fileStream{Body: resp.body, Properties: props, Metadata: md}, nil
}

// getFileContent operation reads or downloads a file from the system
func (f fileServiceClient) getFileContent(path string) (io.ReadCloser, error) {
	resp, err := f.getResourceNoClose(path, compNone, resourceFile, http.MethodGet, nil)
	if err != nil && resp.statusCode != http.StatusNotFound {
		return nil, fmt.Errorf("cannot get resource at %s: %v", path, err)
	}

	switch resp.statusCode {
	case http.StatusOK, http.StatusPartialContent:
		return resp.body, nil
	case http.StatusNotFound:
		resp.body.Close()
		return nil, ErrFileNotFound
	default:
		resp.body.Close()
		return nil, checkRespCode(resp.statusCode, []int{})
	}

}

// returns file properties from the specified HTTP header
func getFileProps(header http.Header) (*fileProperties, error) {
	size, err := strconv.ParseUint(header.Get("Content-Length"), 10, 64)
	if err != nil {
		return nil, err
	}

	return &fileProperties{
		CacheControl:       header.Get("Cache-Control"),
		ContentLength:      size,
		ContentType:        header.Get("Content-Type"),
		CopyCompletionTime: header.Get("x-ms-copy-completion-time"),
		CopyID:             header.Get("x-ms-copy-id"),
		CopyProgress:       header.Get("x-ms-copy-progress"),
		CopySource:         header.Get("x-ms-copy-source"),
		CopyStatus:         header.Get("x-ms-copy-status"),
		CopyStatusDesc:     header.Get("x-ms-copy-status-description"),
		Disposition:        header.Get("Content-Disposition"),
		Encoding:           header.Get("Content-Encoding"),
		Etag:               header.Get("ETag"),
		Language:           header.Get("Content-Language"),
		LastModified:       header.Get("Last-Modified"),
		MD5:                header.Get("Content-MD5"),
	}, nil
}

// returns HTTP header data for the specified directory or share
func (f fileServiceClient) getResourceHeaders(path string, comp compType, res resourceType, verb string) (http.Header, error) {
	resp, err := f.getResourceNoClose(path, comp, res, verb, nil)
	if err != nil {
		return nil, err
	}
	defer resp.body.Close()

	if err = checkRespCode(resp.statusCode, []int{http.StatusOK}); err != nil {
		return nil, err
	}

	return resp.headers, nil
}

// gets the specified resource, doesn't close the response body
func (f fileServiceClient) getResourceNoClose(path string, comp compType, res resourceType, verb string, extraHeaders map[string]string) (*storageResponse, error) {
	params := getURLInitValues(comp, res)
	uri := f.client.getEndpoint(fileServiceName, path, params)
	headers := mergeHeaders(f.client.getStandardHeaders(), extraHeaders)

	return f.client.exec(verb, uri, headers, nil)
}

// merges extraHeaders into headers and returns headers
func mergeHeaders(headers, extraHeaders map[string]string) map[string]string {
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return headers
}

// returns a map of custom metadata values from the specified HTTP header
func getFileMDFromHeaders(header http.Header) map[string]string {
	metadata := make(map[string]string)
	for k, v := range header {
		// Can't trust CanonicalHeaderKey() to munge case
		// reliably. "_" is allowed in identifiers:
		// https://msdn.microsoft.com/en-us/library/azure/dd179414.aspx
		// https://msdn.microsoft.com/library/aa664670(VS.71).aspx
		// http://tools.ietf.org/html/rfc7230#section-3.2
		// ...but "_" is considered invalid by
		// CanonicalMIMEHeaderKey in
		// https://golang.org/src/net/textproto/reader.go?s=14615:14659#L542
		// so k can be "X-Ms-Meta-Foo" or "x-ms-meta-foo_bar".
		k = strings.ToLower(k)
		if len(v) == 0 || !strings.HasPrefix(k, strings.ToLower(userDefinedMetadataHeaderPrefix)) {
			continue
		}
		// metadata["foo"] = content of the last X-Ms-Meta-Foo header
		k = k[len(userDefinedMetadataHeaderPrefix):]
		metadata[k] = v[len(v)-1]
	}
	return metadata
}

const (
	// DefaultBaseURL is the domain name used for storage requests when a
	// default client is created.
	defaultBaseURL = "core.windows.net"

	// DefaultAPIVersion is the  Azure Storage API version string used when a
	// basic client is created.
	defaultAPIVersion = "2015-02-21"

	blobServiceName = "blob"
	fileServiceName = "file"

	userDefinedMetadataHeaderPrefix = "X-Ms-Meta-"
)

// client is the object that needs to be constructed to perform
// operations on the storage account.
type client struct {
	// HTTPClient is the http.Client used to initiate API
	// requests.  If it is nil, http.DefaultClient is used.
	HTTPClient *http.Client

	accountName string
	accountKey  []byte
	baseURL     string
	apiVersion  string
}

type storageResponse struct {
	statusCode int
	headers    http.Header
	body       io.ReadCloser
}

type odataResponse struct {
	storageResponse
	odata odataErrorMessage
}

// AzureStorageServiceError contains fields of the error response from
// Azure Storage Service REST API. See https://msdn.microsoft.com/en-us/library/azure/dd179382.aspx
// Some fields might be specific to certain calls.
type azureStorageServiceError struct {
	Code                      string `xml:"Code"`
	Message                   string `xml:"Message"`
	AuthenticationErrorDetail string `xml:"AuthenticationErrorDetail"`
	QueryParameterName        string `xml:"QueryParameterName"`
	QueryParameterValue       string `xml:"QueryParameterValue"`
	Reason                    string `xml:"Reason"`
	StatusCode                int
	RequestID                 string
}

type odataErrorMessageMessage struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type odataErrorMessageInternal struct {
	Code    string                   `json:"code"`
	Message odataErrorMessageMessage `json:"message"`
}

type odataErrorMessage struct {
	Err odataErrorMessageInternal `json:"odata.error"`
}

// UnexpectedStatusCodeError is returned when a storage service responds with neither an error
// nor with an HTTP status code indicating success.
type unexpectedStatusCodeError struct {
	allowed []int
	got     int
}

func (e unexpectedStatusCodeError) Error() string {
	s := func(i int) string { return fmt.Sprintf("%d %s", i, http.StatusText(i)) }

	got := s(e.got)
	expected := []string{}
	for _, v := range e.allowed {
		expected = append(expected, s(v))
	}
	return fmt.Sprintf("storage: status code from service response is %s; was expecting %s", got, strings.Join(expected, " or "))
}

// Got is the actual status code returned by Azure.
func (e unexpectedStatusCodeError) Got() int {
	return e.got
}

// NewBasicClient constructs a Client with given storage service name and
// key.
func newBasicClient(accountName, accountKey string) (client, error) {
	return newClient(accountName, accountKey, defaultBaseURL, defaultAPIVersion)
}

// NewClient constructs a Client. This should be used if the caller wants
// to specify whether to use HTTPS, a specific REST API version or a custom
// storage endpoint than Azure Public Cloud.
func newClient(accountName, accountKey, blobServiceBaseURL, apiVersion string) (client, error) {
	var c client
	if accountName == "" {
		return c, fmt.Errorf("azure: account name required")
	} else if accountKey == "" {
		return c, fmt.Errorf("azure: account key required")
	} else if blobServiceBaseURL == "" {
		return c, fmt.Errorf("azure: base storage service url required")
	}

	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return c, fmt.Errorf("azure: malformed storage account key: %v", err)
	}

	return client{
		accountName: accountName,
		accountKey:  key,
		baseURL:     blobServiceBaseURL,
		apiVersion:  apiVersion,
	}, nil
}

func (c client) getBaseURL(service string) string {
	scheme := "https"
	host := fmt.Sprintf("%s.%s.%s", c.accountName, service, c.baseURL)

	u := &url.URL{
		Scheme: scheme,
		Host:   host}
	return u.String()
}

func (c client) getEndpoint(service, path string, params url.Values) string {
	u, err := url.Parse(c.getBaseURL(service))
	if err != nil {
		// really should not be happening
		panic(err)
	}

	// API doesn't accept path segments not starting with '/'
	if !strings.HasPrefix(path, "/") {
		path = fmt.Sprintf("/%v", path)
	}

	u.Path = path
	u.RawQuery = params.Encode()
	return u.String()
}

// GetFileService returns a FileServiceClient which can operate on the file
// service of the storage account.
func (c client) newFileService() fileServiceClient {
	return fileServiceClient{c}
}

func (c client) createAuthorizationHeader(canonicalizedString string) string {
	signature := c.computeHmac256(canonicalizedString)
	return fmt.Sprintf("%s %s:%s", "SharedKey", c.getCanonicalizedAccountName(), signature)
}

func (c client) getAuthorizationHeader(verb, url string, headers map[string]string) (string, error) {
	canonicalizedResource, err := c.buildCanonicalizedResource(url)
	if err != nil {
		return "", err
	}

	canonicalizedString := c.buildCanonicalizedString(verb, headers, canonicalizedResource)
	return c.createAuthorizationHeader(canonicalizedString), nil
}

func (c client) getStandardHeaders() map[string]string {
	return map[string]string{
		"x-ms-version": c.apiVersion,
		"x-ms-date":    currentTimeRfc1123Formatted(),
	}
}

func (c client) getCanonicalizedAccountName() string {
	// since we may be trying to access a secondary storage account, we need to
	// remove the -secondary part of the storage name
	return strings.TrimSuffix(c.accountName, "-secondary")
}

func (c client) buildCanonicalizedHeader(headers map[string]string) string {
	cm := make(map[string]string)

	for k, v := range headers {
		headerName := strings.TrimSpace(strings.ToLower(k))
		match, _ := regexp.MatchString("x-ms-", headerName)
		if match {
			cm[headerName] = v
		}
	}

	if len(cm) == 0 {
		return ""
	}

	keys := make([]string, 0, len(cm))
	for key := range cm {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	ch := ""

	for i, key := range keys {
		if i == len(keys)-1 {
			ch += fmt.Sprintf("%s:%s", key, cm[key])
		} else {
			ch += fmt.Sprintf("%s:%s\n", key, cm[key])
		}
	}
	return ch
}

func (c client) buildCanonicalizedResourceTable(uri string) (string, error) {
	errMsg := "buildCanonicalizedResourceTable error: %s"
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf(errMsg, err.Error())
	}

	cr := "/" + c.getCanonicalizedAccountName()

	if len(u.Path) > 0 {
		cr += u.EscapedPath()
	}

	params, err := url.ParseQuery(u.RawQuery)

	// search for "comp" parameter, if exists then add it to canonicalizedresource
	for key := range params {
		if key == "comp" {
			cr += "?comp=" + params[key][0]
		}
	}

	return cr, nil
}

func (c client) buildCanonicalizedResource(uri string) (string, error) {
	errMsg := "buildCanonicalizedResource error: %s"
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf(errMsg, err.Error())
	}

	cr := "/" + c.getCanonicalizedAccountName()

	if len(u.Path) > 0 {
		// Any portion of the CanonicalizedResource string that is derived from
		// the resource's URI should be encoded exactly as it is in the URI.
		// -- https://msdn.microsoft.com/en-gb/library/azure/dd179428.aspx
		cr += u.EscapedPath()
	}

	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf(errMsg, err.Error())
	}

	if len(params) > 0 {
		cr += "\n"
		keys := make([]string, 0, len(params))
		for key := range params {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		for i, key := range keys {
			if len(params[key]) > 1 {
				sort.Strings(params[key])
			}

			if i == len(keys)-1 {
				cr += fmt.Sprintf("%s:%s", key, strings.Join(params[key], ","))
			} else {
				cr += fmt.Sprintf("%s:%s\n", key, strings.Join(params[key], ","))
			}
		}
	}

	return cr, nil
}

func (c client) buildCanonicalizedString(verb string, headers map[string]string, canonicalizedResource string) string {
	contentLength := headers["Content-Length"]
	if contentLength == "0" {
		contentLength = ""
	}
	canonicalizedString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
		verb,
		headers["Content-Encoding"],
		headers["Content-Language"],
		contentLength,
		headers["Content-MD5"],
		headers["Content-Type"],
		headers["Date"],
		headers["If-Modified-Since"],
		headers["If-Match"],
		headers["If-None-Match"],
		headers["If-Unmodified-Since"],
		headers["Range"],
		c.buildCanonicalizedHeader(headers),
		canonicalizedResource)

	return canonicalizedString
}

func (c client) exec(verb, url string, headers map[string]string, body io.Reader) (*storageResponse, error) {
	authHeader, err := c.getAuthorizationHeader(verb, url, headers)
	if err != nil {
		return nil, err
	}

	headers["Authorization"] = authHeader
	req, err := http.NewRequest(verb, url, body)
	if err != nil {
		return nil, errors.New("azure/storage: error creating request: " + err.Error())
	}

	if clstr, ok := headers["Content-Length"]; ok {
		// content length header is being signed, but completely ignored by golang.
		// instead we have to use the ContentLength property on the request struct
		// (see https://golang.org/src/net/http/request.go?s=18140:18370#L536 and
		// https://golang.org/src/net/http/transfer.go?s=1739:2467#L49)
		req.ContentLength, err = strconv.ParseInt(clstr, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	statusCode := resp.StatusCode
	if statusCode >= 400 && statusCode <= 505 {
		var respBody []byte
		respBody, err = readResponseBody(resp)
		if err != nil {
			return nil, err
		}

		requestID := resp.Header.Get("x-ms-request-id")
		if len(respBody) == 0 {
			// no error in response body, might happen in HEAD requests
			err = serviceErrFromStatusCode(resp.StatusCode, resp.Status, requestID)
		} else {
			// response contains storage service error object, unmarshal
			storageErr, errIn := serviceErrFromXML(respBody, resp.StatusCode, requestID)
			if err != nil { // error unmarshaling the error response
				err = errIn
			}
			err = storageErr
		}
		return &storageResponse{
			statusCode: resp.StatusCode,
			headers:    resp.Header,
			body:       ioutil.NopCloser(bytes.NewReader(respBody)), /* restore the body */
		}, err
	}

	return &storageResponse{
		statusCode: resp.StatusCode,
		headers:    resp.Header,
		body:       resp.Body}, nil
}

func (c client) execInternalJSON(verb, url string, headers map[string]string, body io.Reader) (*odataResponse, error) {
	req, err := http.NewRequest(verb, url, body)
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	respToRet := &odataResponse{}
	respToRet.body = resp.Body
	respToRet.statusCode = resp.StatusCode
	respToRet.headers = resp.Header

	statusCode := resp.StatusCode
	if statusCode >= 400 && statusCode <= 505 {
		var respBody []byte
		respBody, err = readResponseBody(resp)
		if err != nil {
			return nil, err
		}

		if len(respBody) == 0 {
			// no error in response body, might happen in HEAD requests
			err = serviceErrFromStatusCode(resp.StatusCode, resp.Status, resp.Header.Get("x-ms-request-id"))
			return respToRet, err
		}
		// try unmarshal as odata.error json
		err = json.Unmarshal(respBody, &respToRet.odata)
		return respToRet, err
	}

	return respToRet, nil
}

func (c client) createSharedKeyLite(url string, headers map[string]string) (string, error) {
	can, err := c.buildCanonicalizedResourceTable(url)

	if err != nil {
		return "", err
	}
	strToSign := headers["x-ms-date"] + "\n" + can

	hmac := c.computeHmac256(strToSign)
	return fmt.Sprintf("SharedKeyLite %s:%s", c.accountName, hmac), nil
}

func (c client) execTable(verb, url string, headers map[string]string, body io.Reader) (*odataResponse, error) {
	var err error
	headers["Authorization"], err = c.createSharedKeyLite(url, headers)
	if err != nil {
		return nil, err
	}

	return c.execInternalJSON(verb, url, headers, body)
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	out, err := ioutil.ReadAll(resp.Body)
	if err == io.EOF {
		err = nil
	}
	return out, err
}

func serviceErrFromXML(body []byte, statusCode int, requestID string) (azureStorageServiceError, error) {
	var storageErr azureStorageServiceError
	if err := xml.Unmarshal(body, &storageErr); err != nil {
		return storageErr, err
	}
	storageErr.StatusCode = statusCode
	storageErr.RequestID = requestID
	return storageErr, nil
}

func serviceErrFromStatusCode(code int, status string, requestID string) azureStorageServiceError {
	return azureStorageServiceError{
		StatusCode: code,
		Code:       status,
		RequestID:  requestID,
		Message:    "no response body was available for error status code",
	}
}

func (e azureStorageServiceError) Error() string {
	return fmt.Sprintf("storage: service returned error: StatusCode=%d, ErrorCode=%s, ErrorMessage=%s, RequestId=%s, QueryParameterName=%s, QueryParameterValue=%s",
		e.StatusCode, e.Code, e.Message, e.RequestID, e.QueryParameterName, e.QueryParameterValue)
}

// checkRespCode returns UnexpectedStatusError if the given response code is not
// one of the allowed status codes; otherwise nil.
func checkRespCode(respCode int, allowed []int) error {
	for _, v := range allowed {
		if respCode == v {
			return nil
		}
	}
	return unexpectedStatusCodeError{allowed, respCode}
}
