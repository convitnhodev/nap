package nap

import (
	"context"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"git.kafefin.net/backend/kitchen/l"

	goquery "github.com/google/go-querystring/query"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	// plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json"
	formContentType = "application/x-www-form-urlencoded"
)

const (
	// hdrUserAgentKey       = "User-Agent"
	// hdrAcceptKey          = "Accept"
	hdrContentTypeKey = "Content-Type"
	// hdrContentLengthKey   = "Content-Length"
	// hdrContentEncodingKey = "Content-Encoding"
	hdrAuthorizationKey = "Authorization"
)

var (
// jsonCheck = regexp.MustCompile(`(?i:(application|text)/(json|.*\+json|json\-.*)(;|$))`)
// xmlCheck  = regexp.MustCompile(`(?i:(application|text)/(xml|.*\+xml)(;|$))`)

// bufPool = &sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
)

// Doer executes http requests.  It is implemented by *http.Client.  You can
// wrap *http.Client with layers of Doers to form a stack of client-side
// middleware.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Nap is an HTTP Request builder and sender.
type Nap struct {
	// context
	ctx context.Context
	// http Client for doing requests
	httpClient Doer
	// HTTP method (GET, POST, etc.)
	method string
	// base url string for requests
	baseURL *url.URL
	// raw url string for requests
	rawURL string
	// stores key-values pairs to add to request's Headers
	header http.Header
	// url tagged query structs
	queryStructs []interface{}
	queryParams  map[string]string
	// body provider
	bodyProvider          BodyProvider
	multipartBodyProvider BodyMultipartProvider
	// response decoder
	responseDecoder ResponseDecoder
	// func success decider
	isSuccess SuccessDecider

	counterVec *prometheus.CounterVec
	log        l.Logger
}

var defaultClient = &http.Client{ // otelhttp.DefaultClient
	Transport: http.DefaultTransport,
}

// New returns a new Nap with an http defaultClient.
func New() *Nap {
	return &Nap{
		httpClient:      defaultClient,
		method:          http.MethodGet,
		header:          make(http.Header),
		queryStructs:    make([]interface{}, 0),
		queryParams:     make(map[string]string),
		responseDecoder: jsonDecoder{},
		isSuccess:       DecodeOnSuccess,
		log:             l.New(),
	}
}

// New returns a new Nap with an otelhttp
func NewOtel(opts ...otelhttp.Option) *Nap {
	otelClient := &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport, opts...),
	}
	return New().Client(otelClient)
}

func (s Nap) Clone() *Nap {
	// copy Headers pairs into new Header map
	headerCopy := make(http.Header)
	for k, v := range s.header {
		headerCopy[k] = v
	}

	baseURL, _ := url.Parse(s.baseURL.String())
	return &Nap{
		ctx:             s.ctx,
		httpClient:      s.httpClient,
		method:          s.method,
		baseURL:         baseURL,
		rawURL:          s.rawURL,
		header:          headerCopy,
		queryStructs:    append([]interface{}{}, s.queryStructs...),
		bodyProvider:    s.bodyProvider,
		queryParams:     s.queryParams,
		responseDecoder: s.responseDecoder,
		isSuccess:       s.isSuccess,
		counterVec:      s.counterVec,
		log:             s.log,
	}
}

// Http Client

// Client sets the http Client used to do requests. If a nil client is given,
// the http.defaultClient will be used.
func (s *Nap) Client(httpClient *http.Client) *Nap {
	if httpClient == nil {
		return s.Doer(defaultClient)
	}

	return s.Doer(httpClient)
}

// Doer sets the custom Doer implementation used to do requests.
// If a nil client is given, the http.defaultClient will be used.
func (s *Nap) Doer(doer Doer) *Nap {
	if doer == nil {
		s.httpClient = defaultClient
	} else {
		s.httpClient = doer
	}
	return s
}

// Context method returns the Context if its already set in request
// otherwise it creates new one using `context.Background()`.
func (s *Nap) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *Nap) AutoRetry(opts ...RetryOption) *Nap {
	s.httpClient = NewRetryDoer(s.httpClient, s.log, opts...)
	return s
}

// SetContext method sets the context.Context for current Request. It allows
// to interrupt the request execution if ctx.Done() channel is closed.
// See https://blog.golang.org/context article and the "context" package
// documentation.
func (s *Nap) SetContext(ctx context.Context) *Nap {
	s.ctx = ctx
	return s
}

// Debug ...
func (s *Nap) Debug() *Nap {
	return s
}

// CreatePromethuesVec return to register once time: prometheus.MustRegister(counterVec)
func (s *Nap) CreatePromethuesVec(existingVec *prometheus.CounterVec) *prometheus.CounterVec {
	if existingVec != nil {
		s.counterVec = existingVec
		return existingVec
	}

	s.counterVec = NapCounterVec()
	return s.counterVec
}

func NapCounterVec() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nap_counter",
	}, []string{"method", "host", "path", "status_code"})
}

// Method

// Head sets the Nap method to HEAD and sets the given pathURL.
func (s *Nap) Head(pathURL string) *Nap {
	s.method = http.MethodHead
	return s.Path(pathURL)
}

// Get sets the Nap method to GET and sets the given pathURL.
func (s *Nap) Get(pathURL string) *Nap {
	s.method = http.MethodGet
	return s.Path(pathURL)
}

// Post sets the Nap method to POST and sets the given pathURL.
func (s *Nap) Post(pathURL string) *Nap {
	s.method = http.MethodPost
	return s.Path(pathURL)
}

// Put sets the Nap method to PUT and sets the given pathURL.
func (s *Nap) Put(pathURL string) *Nap {
	s.method = http.MethodPut
	return s.Path(pathURL)
}

// Patch sets the Nap method to PATCH and sets the given pathURL.
func (s *Nap) Patch(pathURL string) *Nap {
	s.method = http.MethodPatch
	return s.Path(pathURL)
}

// Delete sets the Nap method to DELETE and sets the given pathURL.
func (s *Nap) Delete(pathURL string) *Nap {
	s.method = http.MethodDelete
	return s.Path(pathURL)
}

// Options sets the Nap method to OPTIONS and sets the given pathURL.
func (s *Nap) Options(pathURL string) *Nap {
	s.method = http.MethodOptions
	return s.Path(pathURL)
}

// Header

func (s *Nap) AddHeader(key, value string) *Nap {
	s.header.Add(key, value)
	return s
}

func (s *Nap) SetHeader(key, value string) *Nap {
	s.header.Set(key, value)
	return s
}

func (s *Nap) SetHeaders(headers map[string]string) *Nap {
	for h, v := range headers {
		s.header.Set(h, v)
	}
	return s
}

func (s *Nap) SetBasicAuth(username, password string) *Nap {
	return s.SetHeader(hdrAuthorizationKey, "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
}

func (s *Nap) SetAuthToken(token string) *Nap {
	return s.SetHeader(hdrAuthorizationKey, "Bearer "+token)
}

func (s *Nap) WithSuccessDecider(isSuccess SuccessDecider) *Nap {
	s.isSuccess = isSuccess
	return s
}

// Url

// Base sets the baseURL. If you intend to extend the url with Path,
// baseUrl should be specified with a trailing slash.
func (s *Nap) Base(baseURL string) *Nap {
	var err error
	s.baseURL, err = url.Parse(baseURL)
	if err != nil {
		panic(err)
	}

	s.rawURL = s.baseURL.String()
	return s
}

// Path extends the rawURL with the given path by resolving the reference to
// an absolute URL. If parsing errors occur, the rawURL is left unmodified.
func (s *Nap) Path(path string) *Nap {
	var err error
	pathURL := &url.URL{}
	if s.baseURL == nil {
		s.baseURL, err = url.Parse(path)
		if err != nil {
			return s
		}

		pathURL = s.baseURL
	} else {
		pathURL, err = url.Parse(path)
		if err != nil {
			return s
		}
	}

	s.rawURL = s.baseURL.ResolveReference(pathURL).String()
	if strings.HasSuffix(path, "/") && !strings.HasSuffix(s.rawURL, "/") {
		s.rawURL += "/"
	}
	return s
}

// QueryStruct appends the queryStruct to the Nap's queryStructs. The value
// pointed to by each queryStruct will be encoded as url query parameters on
// new requests (see Request()).
// The queryStruct argument should be a pointer to a url tagged struct. See
// https://godoc.org/github.com/google/go-querystring/query for details.
func (s *Nap) QueryStruct(queryStruct interface{}) *Nap {
	if queryStruct != nil {
		s.queryStructs = append(s.queryStructs, queryStruct)
	}
	s.log.Info("QueryStruct", l.String(s.method, s.rawURL), l.Object("body", s.queryStructs))
	return s
}

func (s *Nap) QueryParams(params map[string]string) *Nap {
	if params != nil {
		s.queryParams = params
	}
	s.log.Info("QueryParams", l.String(s.method, s.rawURL), l.Object("body", s.queryParams))
	return s
}

// Body

// Body sets the Nap's body. The body value will be set as the Body on new
// requests (see Request()).
// If the provided body is also an io.Closer, the request Body will be closed
// by http.Client methods.
func (s *Nap) Body(body io.Reader) *Nap {
	if body == nil {
		return s
	}
	return s.BodyProvider(bodyProvider{body: body})
}

// BodyProvider sets the Nap's body provider.
func (s *Nap) BodyProvider(body BodyProvider) *Nap {
	if body == nil {
		return s
	}

	s.bodyProvider = body
	s.multipartBodyProvider = nil

	ct := body.ContentType()
	if ct != "" {
		s.SetHeader(hdrContentTypeKey, ct)
	}

	return s
}

// BodyMultipartProvider ...
func (s *Nap) BodyMultipartProvider(body BodyMultipartProvider) *Nap {
	if body == nil {
		return s
	}

	s.bodyProvider = nil
	s.multipartBodyProvider = body

	return s
}

// BodyJSON sets the Nap's bodyJSON. The value pointed to by the bodyJSON
// will be JSON encoded as the Body on new requests (see Request()).
// The bodyJSON argument should be a pointer to a JSON tagged struct. See
// https://golang.org/pkg/encoding/json/#MarshalIndent for details.
func (s *Nap) BodyJSON(bodyJSON interface{}) *Nap {
	if bodyJSON == nil {
		return s
	}
	return s.BodyProvider(jsonBodyProvider{payload: bodyJSON})
}

// BodyForm sets the Nap's bodyForm. The value pointed to by the bodyForm
// will be url encoded as the Body on new requests (see Request()).
// The bodyForm argument should be a pointer to a url tagged struct. See
// https://godoc.org/github.com/google/go-querystring/query for details.
func (s *Nap) BodyForm(bodyForm interface{}) *Nap {
	if bodyForm == nil {
		return s
	}
	return s.BodyProvider(formBodyProvider{payload: bodyForm})
}

// BodyUrlEncode ...
func (s *Nap) BodyUrlEncode(values map[string]string) *Nap {
	if values == nil {
		return s
	}
	return s.BodyProvider(formUrlEncodedProvider{values: values})
}

// BodyMultipart ...
func (s *Nap) BodyMultipart(payload, filePayload map[string]io.Reader) *Nap {
	if payload == nil && filePayload == nil {
		return s
	}
	return s.BodyMultipartProvider(multipartDataBodyProvider{payload: payload, filePayload: filePayload})
}

// Requests

// Request returns a new http.Request created with the Nap properties.
// Returns any errors parsing the rawURL, encoding query structs, encoding
// the body, or creating the http.Request.
func (s *Nap) Request() (*http.Request, error) {
	reqURL, err := url.Parse(s.rawURL)
	if err != nil {
		return nil, err
	}

	err = buildQueryParamUrl(reqURL, s.queryStructs, s.queryParams)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if s.multipartBodyProvider != nil {
		var ct string
		body, ct, err = s.multipartBodyProvider.Body()
		if err != nil {
			return nil, err
		}
		s.header.Set(hdrContentTypeKey, ct)
	} else if s.bodyProvider != nil {
		body, err = s.bodyProvider.Body()
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(s.Context(), s.method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}
	addHeaders(req, s.header)
	return req, err
}

// buildQueryParamUrl parses url tagged query structs using go-querystring to
// encode them to url.Values and format them onto the url.RawQuery. Any
// query parsing or encoding errors are returned.
func buildQueryParamUrl(reqURL *url.URL, queryStructs []interface{}, queryParams map[string]string) error {
	urlValues, err := url.ParseQuery(reqURL.RawQuery)
	if err != nil {
		return err
	}
	// encodes query structs into a url.Values map and merges maps
	for _, queryStruct := range queryStructs {
		queryValues, err := goquery.Values(queryStruct)
		if err != nil {
			return err
		}
		for key, values := range queryValues {
			for _, value := range values {
				urlValues.Add(key, value)
			}
		}
	}
	for k, v := range queryParams {
		urlValues.Add(k, v)
	}
	// url.Values format to a sorted "url encoded" string, e.g. "key=val&foo=bar"
	reqURL.RawQuery = urlValues.Encode()
	return nil
}

// addHeaders adds the key, value pairs from the given http.Header to the
// request. Values for existing keys are appended to the keys values.
func addHeaders(req *http.Request, header http.Header) {
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}

// Sending

// ResponseDecoder sets the Nap's response decoder.
func (s *Nap) ResponseDecoder(decoder ResponseDecoder) *Nap {
	if decoder == nil {
		return s
	}
	s.responseDecoder = decoder
	return s
}

// ReceiveSuccess creates a new HTTP request and returns the response. Success
// responses (2XX) are JSON decoded into the value pointed to by successV.
// Any error creating the request, sending it, or decoding a 2XX response
// is returned.
func (s *Nap) ReceiveSuccess(successV interface{}) (*Response, error) {
	return s.Receive(successV, nil)
}

// Receive creates a new HTTP request and returns the response. Success
// responses (2XX) are JSON decoded into the value pointed to by successV and
// other responses are JSON decoded into the value pointed to by failureV.
// If the status code of response is 204(no content), decoding is skipped.
// Any error creating the request, sending it, or decoding the response is
// returned.
// Receive is shorthand for calling Request and Do.
func (s *Nap) Receive(successV, failureV interface{}) (*Response, error) {
	req, err := s.Request()
	if err != nil {
		return nil, err
	}
	return s.Do(req, successV, failureV)
}

// Do send an HTTP request and returns the response. Success responses (2XX)
// are JSON decoded into the value pointed to by successV and other responses
// are JSON decoded into the value pointed to by failureV.
// If the status code of response is 204(no content), decoding is skipped.
// Any error sending the request or decoding the response is returned.
func (s *Nap) Do(req *http.Request, successV, failureV interface{}) (*Response, error) {
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return NewResponse(resp), err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	// The default HTTP client's Transport may not
	// reuse HTTP/1.x "keep-alive" TCP connections if the Body is
	// not read to completion and closed.
	// See: https://golang.org/pkg/net/http/#Response
	//nolint:errcheck
	defer io.Copy(ioutil.Discard, resp.Body)

	// Don't try to decode on 204s
	if resp.StatusCode == http.StatusNoContent {
		return NewResponse(resp), nil
	}

	// Decode from json
	if successV != nil || failureV != nil {
		err = s.decodeResponse(resp, successV, failureV)
	}
	return NewResponse(resp), err
}

// decodeResponse decodes response Body into the value pointed to by successV
// if the response is a success (2XX) or into the value pointed to by failureV
// otherwise. If the successV or failureV argument to decode into is nil,
// decoding is skipped.
// Caller is responsible for closing the resp.Body.
func (s *Nap) decodeResponse(resp *http.Response, successV, failureV interface{}) error {
	if s.counterVec != nil {
		s.counterVec.WithLabelValues(s.method, s.baseURL.Host, s.rawURL, strconv.Itoa(resp.StatusCode)).Add(1)
	}

	if s.isSuccess(resp) {
		switch sv := successV.(type) {
		case nil:
			return nil
		case *Raw:
			respBody, err := ioutil.ReadAll(resp.Body)
			*sv = respBody
			s.log.Info("decode success-raw", l.String(s.method, s.rawURL), l.ByteString("resp", respBody), l.Error(err))
			return err
		default:
			err := s.responseDecoder.Decode(resp, successV)
			s.log.Info("decode success-resp", l.String(s.method, s.rawURL), l.Object("resp", successV), l.Error(err))
			return err
		}
	} else {
		switch fv := failureV.(type) {
		case nil:
			respBody, err := ioutil.ReadAll(resp.Body)
			s.log.Warn("decode failure-nil", l.String(s.method, s.rawURL), l.String("status", resp.Status), l.ByteString("resp", respBody), l.Error(err))
			return nil
		case *Raw:
			respBody, err := ioutil.ReadAll(resp.Body)
			*fv = respBody
			s.log.Warn("decode failure-raw", l.String(s.method, s.rawURL), l.String("status", resp.Status), l.ByteString("resp", respBody), l.Error(err))
			return err
		default:
			err := s.responseDecoder.Decode(resp, failureV)
			s.log.Warn("decode failure-resp", l.String(s.method, s.rawURL), l.String("status", resp.Status), l.Object("resp", failureV), l.Error(err))
			return err
		}
	}
}
