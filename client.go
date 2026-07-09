// Package turnkey provides a client for interacting with the Turnkey API.
package turnkey

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

//go:embed VERSION
var embeddedVersion string

var DefaultClientVersion = "go-sdk/" + strings.TrimSpace(embeddedVersion)

const (
	defaultBaseURL      = "https://api.turnkey.com"
	defaultAuthProxyURL = "https://authproxy.turnkey.com"
	defaultHTTPTimeout  = 30 * time.Second
)

type urlConfig struct {
	baseURL          string
	authProxyBaseURL string
}

type httpConfig struct {
	maxRetries int
	retryDelay time.Duration
}

type pollConfig struct {
	interval time.Duration
	timeout  time.Duration
}

type config struct {
	organizationID    string
	authProxyConfigID string
	stamper           Stamper
	httpClient        *http.Client
	logger            Logger
	clientVersion     string

	urls          urlConfig
	http          httpConfig
	activityPoll  pollConfig
	mfaPoll       pollConfig
	consensusPoll pollConfig
}

type activityTyper interface {
	ActivityType() string
}

type defaultLogger struct{}

func (d *defaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// Logger defines a minimal logging interface.
type Logger interface {
	Printf(format string, v ...interface{})
}

type loggingRoundTripper struct {
	inner  http.RoundTripper
	logger Logger
}

// RoundTrip implements http.RoundTripper, logging any errors from the request.
func (lrt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := lrt.inner.RoundTrip(req)
	if err != nil {
		lrt.logger.Printf("Request failed: %v", err)
		return nil, err
	}

	return resp, nil
}

// OptionFunc defines a function which sets configuration options for a Client.
type OptionFunc func(c *config) error

// WithLogger sets a custom logger for the SDK.
func WithLogger(logger Logger) OptionFunc {
	return func(c *config) error {
		c.logger = logger
		return nil
	}
}

// WithBaseURL overrides the Turnkey API base URL.
func WithBaseURL(baseURL string) OptionFunc {
	return func(c *config) error {
		c.urls.baseURL = strings.TrimRight(baseURL, "/")
		return nil
	}
}

// WithAuthProxyBaseURL overrides the Turnkey Auth Proxy base URL.
func WithAuthProxyBaseURL(baseURL string) OptionFunc {
	return func(c *config) error {
		c.urls.authProxyBaseURL = strings.TrimRight(baseURL, "/")
		return nil
	}
}

// WithAuthProxyConfigID sets the Auth Proxy config ID header value.
func WithAuthProxyConfigID(configID string) OptionFunc {
	return func(c *config) error {
		c.authProxyConfigID = configID
		return nil
	}
}

// DefaultAuthProxyConfigID returns the configured Auth Proxy config ID, nil if not set.
func (c *Client) DefaultAuthProxyConfigID() *string {
	if c.config.authProxyConfigID != "" {
		return &c.config.authProxyConfigID
	}

	return nil
}

// WithHTTPClient sets the HTTP client used by the SDK.
func WithHTTPClient(httpClient *http.Client) OptionFunc {
	return func(c *config) error {
		c.httpClient = httpClient
		return nil
	}
}

// WithHTTPRetries sets the number of retries for transient HTTP errors (5xx, network failures).
func WithHTTPRetries(n int) OptionFunc {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("httpMaxRetries must be >= 0, got %d", n)
		}

		c.http.maxRetries = n

		return nil
	}
}

// WithHTTPRetryDelay sets the base delay for HTTP retry backoff.
func WithHTTPRetryDelay(d time.Duration) OptionFunc {
	return func(c *config) error {
		c.http.retryDelay = d
		return nil
	}
}

// WithActivityPollInterval sets the activity polling interval.
func WithActivityPollInterval(interval time.Duration) OptionFunc {
	return func(c *config) error {
		c.activityPoll.interval = interval
		return nil
	}
}

// WithActivityPollTimeout sets the activity polling timeout.
func WithActivityPollTimeout(timeout time.Duration) OptionFunc {
	return func(c *config) error {
		c.activityPoll.timeout = timeout
		return nil
	}
}

// WithMFAPollInterval sets the MFA polling interval.
func WithMFAPollInterval(interval time.Duration) OptionFunc {
	return func(c *config) error {
		c.mfaPoll.interval = interval
		return nil
	}
}

// WithMFAPollTimeout sets the MFA polling timeout.
func WithMFAPollTimeout(timeout time.Duration) OptionFunc {
	return func(c *config) error {
		c.mfaPoll.timeout = timeout
		return nil
	}
}

func WithMFAPolling(interval, timeout time.Duration) OptionFunc {
	return func(c *config) error {
		if interval <= 0 || timeout <= 0 {
			return fmt.Errorf("MFA interval and timeout must both be > 0")
		}

		c.mfaPoll.interval = interval
		c.mfaPoll.timeout = timeout

		return nil
	}
}

func WithConsensusPolling(interval, timeout time.Duration) OptionFunc {
	return func(c *config) error {
		if interval <= 0 || timeout <= 0 {
			return fmt.Errorf("consensus interval and timeout must both be > 0")
		}

		c.consensusPoll.interval = interval
		c.consensusPoll.timeout = timeout

		return nil
	}
}

// NewClient returns a new Turnkey API client.
// stamper signs each authenticated request; pass nil only if the client will not make signed requests.
// organizationID sets the default organization; it may be overridden per-request.
func NewClient(stamper Stamper, organizationID string, options ...OptionFunc) (*Client, error) {
	cfg := &config{
		organizationID: organizationID,
		stamper:        stamper,
		httpClient:     http.DefaultClient,
		logger:         &defaultLogger{},
		clientVersion:  DefaultClientVersion,
		urls: urlConfig{
			baseURL:          defaultBaseURL,
			authProxyBaseURL: defaultAuthProxyURL,
		},
		http: httpConfig{
			maxRetries: 3,
			retryDelay: 100 * time.Millisecond,
		},
		activityPoll: pollConfig{
			interval: time.Second,
			timeout:  2 * time.Minute,
		},
		mfaPoll: pollConfig{
			interval: 0,
			timeout:  0,
		},
		consensusPoll: pollConfig{
			interval: 0,
			timeout:  0,
		},
	}

	for _, option := range options {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.urls.baseURL == "" {
		return nil, errors.New("base URL is required")
	}

	if cfg.urls.authProxyBaseURL == "" {
		return nil, errors.New("auth proxy base URL is required")
	}

	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}

	if cfg.logger == nil {
		cfg.logger = &defaultLogger{}
	}

	transport := cfg.httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	timeout := cfg.httpClient.Timeout
	if timeout == 0 {
		timeout = defaultHTTPTimeout
	}

	cfg.httpClient = &http.Client{
		Transport: &loggingRoundTripper{inner: transport, logger: cfg.logger},
		Timeout:   timeout,
	}

	return &Client{config: cfg}, nil
}

// Client provides a handle by which to interact with the Turnkey API.
type Client struct {
	config *config
}

// BaseURL returns the configured Turnkey API base URL.
func (c *Client) BaseURL() string {
	return c.config.urls.baseURL
}

// AuthProxyBaseURL returns the configured Turnkey Auth Proxy base URL.
func (c *Client) AuthProxyBaseURL() string {
	return c.config.urls.authProxyBaseURL
}

// ClientVersion returns the configured client version header value.
func (c *Client) ClientVersion() string {
	return c.config.clientVersion
}

// DefaultOrganization returns the configured organization ID, or nil if none was set.
func (c *Client) DefaultOrganization() *string {
	if c.config.organizationID != "" {
		return &c.config.organizationID
	}

	return nil
}

func (c *Client) organizationID(inputOrganizationID string) (string, error) {
	if inputOrganizationID != "" {
		return inputOrganizationID, nil
	}

	if org := c.DefaultOrganization(); org != nil {
		return *org, nil
	}

	return "", errors.New("organizationId is required; set OrganizationID on the request or initialize the client with a default organization ID")
}

// classifyActivity categorizes an activity type (consensus needed, failed, completed, etc.) and extracts the typed result if available.
func classifyActivity(activity *Activity) (*Activity, bool, error) {
	switch activity.Status {
	case ActivityStatusCompleted:
		return activity, true, nil
	case ActivityStatusFailed, ActivityStatusRejected:
		return nil, true, &ActivityFailedError{
			ActivityID: activity.ID,
			Status:     activity.Status,
			Failure:    activity.Failure,
		}
	case ActivityStatusConsensusNeeded, ActivityStatusAuthenticatorsNeeded:
		return nil, true, &ActivityRequiresApprovalError{ActivityID: activity.ID, Activity: *activity}
	case ActivityStatusPending, ActivityStatusCreated:
		return nil, false, nil
	default:
		return nil, true, fmt.Errorf("unexpected activity status: %s", activity.Status)
	}
}

func activityAndWait[T any](ctx context.Context, c *Client, reply *ActivityResult[T], extract func(Result) *T) (*T, *Activity, error) {
	if _, done, err := classifyActivity(&reply.Activity); err != nil {
		return nil, nil, err // failed / rejected / consensus-needed
	} else if done {
		result := extract(reply.Activity.Result)
		if result == nil {
			return nil, nil, fmt.Errorf("activity %s completed with nil result", reply.Activity.ID)
		}

		return result, &reply.Activity, nil
	}

	// Pending or created -> poll
	activity, err := c.waitActivity(ctx, reply.Activity.ID)
	if err != nil {
		return nil, nil, err
	}

	result := extract(activity.Result)
	if result == nil {
		return nil, nil, fmt.Errorf("activity %s completed with nil result", activity.ID)
	}

	return result, activity, nil
}

// activityAndWaitNoResult polls an activity with no typed result until it completes, returning the final Activity.
func activityAndWaitNoResult(ctx context.Context, c *Client, reply *ActivityResult[map[string]any]) (*Activity, error) {
	if reply.Activity.Status == ActivityStatusCompleted {
		return &reply.Activity, nil
	}

	return c.waitActivity(ctx, reply.Activity.ID)
}

// postJSON sends a POST request with a JSON body and decodes the JSON response.
func (c *Client) postJSON(ctx context.Context, baseURL string, path string, body any, out any, sign bool, extraHeaders map[string]string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	var stamp *Stamp
	if sign {
		stamp, err = c.stamp(ctx, data)
		if err != nil {
			return err
		}
	}

	respBody, err := c.postWithRetry(ctx, baseURL, path, data, stamp, extraHeaders)
	if err != nil {
		return err
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}

	return json.Unmarshal(respBody, out)
}

// postWithRetry sends a POST request with the given body and retries with exponential backoff.
func (c *Client) postWithRetry(ctx context.Context, baseURL, path string, data []byte, stamp *Stamp, extraHeaders map[string]string) ([]byte, error) {
	const maxRetryDelay = 5 * time.Second

	delay := c.config.http.retryDelay

	var lastErr error

	for attempt := 0; attempt <= c.config.http.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay = min(delay*2, maxRetryDelay)
			}
		}

		respBody, retryable, err := c.postAttempt(ctx, baseURL, path, data, stamp, extraHeaders)
		if err == nil {
			return respBody, nil
		}

		if !retryable {
			return nil, err
		}

		lastErr = err
	}

	return nil, fmt.Errorf("after %d attempts: %w", c.config.http.maxRetries+1, lastErr)
}

// postAttempt sends a single POST request and returns whether the error is retryable.
func (c *Client) postAttempt(ctx context.Context, baseURL, path string, data []byte, stamp *Stamp, extraHeaders map[string]string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Version", c.config.clientVersion)

	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	if stamp != nil {
		req.Header.Set(stamp.HeaderName, stamp.HeaderValue)
	}

	resp, err := c.config.httpClient.Do(req)
	if err != nil {
		return nil, true, err
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil && readErr == nil {
		readErr = closeErr
	}

	if readErr != nil {
		return nil, true, readErr
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		reqErr := newRequestError(resp.StatusCode, respBody)
		return nil, resp.StatusCode >= 500, reqErr
	}

	return respBody, false, nil
}

// signedRequest creates a SignedRequest for the given path and body, signing it if requested.
func (c *Client) signedRequest(ctx context.Context, baseURL string, path string, body any, sign bool) (*SignedRequest, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	var stamp *Stamp
	if sign {
		stamp, err = c.stamp(ctx, data)
		if err != nil {
			return nil, err
		}
	}

	sr := &SignedRequest{
		URL:   strings.TrimRight(baseURL, "/") + path,
		Body:  string(data),
		Stamp: stamp,
		Type:  RequestTypeActivity,
	}

	return sr, nil
}

// newRequestError creates a RequestError by parsing the Turnkey API error response body.
func newRequestError(statusCode int, body []byte) error {
	var parsed errorResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return &RequestError{StatusCode: statusCode, Body: body}
	}

	return &RequestError{
		StatusCode: statusCode,
		Status: &RPCStatus{
			Code:    parsed.Code,
			Message: parsed.Message,
			Details: parsed.Details,
		},
		Body: body,
	}
}

// decodeActivityResponse decodes the raw JSON response from an activity request into an ActivityResult with a typed result.
func decodeActivityResponse[T any](raw map[string]any, resultType string, out *ActivityResult[T]) error {
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	var envelope ActivityResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}

	out.Activity = envelope.Activity

	if len(resultType) == 0 {
		return nil
	}

	result, err := extractActivityResult[T](raw, resultType)
	if err != nil {
		return err
	}

	out.Result = result

	return nil
}

// extractActivityResult extracts the typed result from the raw JSON response of an activity request based on the result type.
func extractActivityResult[T any](raw map[string]any, resultType string) (*T, error) {
	activityRaw, ok := raw["activity"].(map[string]any)
	if !ok {
		return nil, nil
	}

	resultRaw, ok := activityRaw["result"].(map[string]any)
	if !ok {
		return nil, nil
	}

	resultField := strings.ToLower(resultType[:1]) + resultType[1:]

	value, ok := resultRaw[resultField]
	if !ok || value == nil {
		return nil, nil
	}

	resultData, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var result T
	if err := json.Unmarshal(resultData, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// stamp generates a Stamp for the given request body by signing it with the configured Stamper.
func (c *Client) stamp(ctx context.Context, body []byte) (*Stamp, error) {
	if c.config.stamper == nil {
		return nil, errors.New("stamper is required for signed Turnkey requests")
	}

	return c.config.stamper.Stamp(ctx, body)
}

// activityEnvelope creates the JSON envelope for an activity request, extracting the organization ID and timestamp from the input if available.
func (c *Client) activityEnvelope(input activityTyper) (map[string]any, error) {
	body, err := toMap(input)
	if err != nil {
		return nil, err
	}

	var inputOrgID string
	if v, ok := body["organizationId"].(string); ok {
		inputOrgID = v
	}

	organizationID, err := c.organizationID(inputOrgID)
	if err != nil {
		return nil, err
	}

	var timestampMs string
	if v, ok := body["timestampMs"].(string); ok {
		timestampMs = v
	}

	if timestampMs == "" {
		timestampMs = fmt.Sprintf("%d", time.Now().UnixMilli())
	}

	delete(body, "organizationId")
	delete(body, "timestampMs")
	delete(body, "parameters")

	return map[string]any{
		"type":           input.ActivityType(),
		"timestampMs":    timestampMs,
		"organizationId": organizationID,
		"parameters":     body,
	}, nil
}

// topMap converts a struct to a map[string]any by JSON-marshaling and unmarshaling it.
func toMap(input any) (map[string]any, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	for key, value := range out {
		if value == nil {
			delete(out, key)
		}
	}

	return out, nil
}

// waitActivity polls an activity until it reaches a final status.
// If consensus polling is configured and the activity hits CONSENSUS_NEEDED,
// it transitions to pollConsensus until terminal or consensus timeout.
// If the activity hits AUTHENTICATORS_NEEDED, it transitions to pollMFA.
func (c *Client) waitActivity(ctx context.Context, activityID string) (*Activity, error) {
	activity, err := c.pollActivity(ctx, activityID)
	if err != nil {
		return activity, err
	}

	switch activity.Status {
	case ActivityStatusConsensusNeeded:
		if c.config.consensusPoll.interval == 0 || c.config.consensusPoll.timeout == 0 {
			return nil, &ActivityRequiresApprovalError{ActivityID: activity.ID, Activity: *activity}
		}

		return c.pollConsensus(ctx, activity)
	case ActivityStatusAuthenticatorsNeeded:
		if c.config.mfaPoll.interval == 0 || c.config.mfaPoll.timeout == 0 {
			return nil, &ActivityRequiresApprovalError{ActivityID: activity.ID, Activity: *activity}
		}

		return c.pollMFA(ctx, activity)
	default:
		return activity, nil
	}
}

// pollConsensus polls an activity in CONSENSUS_NEEDED status until it reaches a terminal status,
// returning an error if the consensus timeout is reached first.
func (c *Client) pollConsensus(ctx context.Context, latest *Activity) (*Activity, error) {
	deadline := time.NewTimer(c.config.consensusPoll.timeout)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, &ActivityRequiresApprovalError{ActivityID: latest.ID, Activity: *latest}
		case <-time.After(c.config.consensusPoll.interval):
		}

		activity, err := c.GetActivity(ctx, GetActivityRequest{ActivityID: latest.ID})
		if err != nil {
			return nil, err
		}

		if activity.Activity.Status != ActivityStatusConsensusNeeded {
			result, _, err := classifyActivity(&activity.Activity)
			return result, err
		}

		latest = &activity.Activity
	}
}

// pollActivity polls at the activity-poll cadence with exponential backoff.
// Returns when the activity reaches any terminal status, CONSENSUS_NEEDED is
// or AUTHENTICATORS_NEEDED are returned to the caller so they can transition
// to their dedicated polling phases.
func (c *Client) pollActivity(ctx context.Context, activityID string) (*Activity, error) {
	deadline := time.NewTimer(c.config.activityPoll.timeout)
	defer deadline.Stop()

	delay := c.config.activityPoll.interval

	const maxDelay = 5 * time.Second

	for {
		activity, err := c.GetActivity(ctx, GetActivityRequest{ActivityID: activityID})
		if err != nil {
			return nil, err
		}

		if activity.Activity.Status == ActivityStatusConsensusNeeded ||
			activity.Activity.Status == ActivityStatusAuthenticatorsNeeded {
			return &activity.Activity, nil
		}

		if result, done, err := classifyActivity(&activity.Activity); done {
			return result, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("timed out waiting for activity %s", activityID)
		case <-time.After(delay):
		}

		delay = min(delay*2, maxDelay)
	}
}

// pollMFA polls an activity in AUTHENTICATORS_NEEDED status until it reaches a terminal status,
// returning an approval-required error if the MFA timeout is reached first.
func (c *Client) pollMFA(ctx context.Context, latest *Activity) (*Activity, error) {
	deadline := time.NewTimer(c.config.mfaPoll.timeout)
	defer deadline.Stop()

	delay := c.config.mfaPoll.interval

	const maxDelay = 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, &ActivityRequiresApprovalError{ActivityID: latest.ID, Activity: *latest}
		case <-time.After(delay):
		}

		activity, err := c.GetActivity(ctx, GetActivityRequest{ActivityID: latest.ID})
		if err != nil {
			return nil, err
		}

		if activity.Activity.Status != ActivityStatusAuthenticatorsNeeded {
			result, _, err := classifyActivity(&activity.Activity)
			return result, err
		}

		latest = &activity.Activity
		delay = min(delay*2, maxDelay)
	}
}
