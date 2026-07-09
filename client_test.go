package turnkey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tkcrypto "github.com/tkhq/go-sdk/crypto"
)

const testWalletName = "wallet"

type testActivityRequest struct {
	OrganizationID string `json:"organizationId,omitempty"`
	Name           string `json:"name,omitempty"`
}

func (testActivityRequest) ActivityType() string { return "ACTIVITY_TYPE_TEST" }

// toMap

func TestToMap_ZeroValues(t *testing.T) {
	type myStruct struct {
		Field string `json:"field"`
	}

	out, err := toMap(myStruct{Field: ""})
	require.NoError(t, err)
	assert.Equal(t, "", out["field"])
} // zero strings should stay

func TestToMap_NilPointerDropped(t *testing.T) {
	type myStruct struct {
		Field *string `json:"field,omitempty"`
	}

	out, err := toMap(myStruct{Field: nil})
	require.NoError(t, err)

	_, exists := out["field"]
	assert.False(t, exists)
} // *string nil should be gone

func TestToMap_NonMarshalable(t *testing.T) {
	type myStruct struct {
		Field chan int `json:"field"`
	}

	_, err := toMap(myStruct{Field: make(chan int)})
	require.Error(t, err)
} // channels -> expect error

// ActivityEnvelope tests
func TestActivityEnvelope_OrgFromInput(t *testing.T) {
	c, err := NewClient(nil, "client-org", WithHTTPRetries(0))
	require.NoError(t, err)

	env, err := c.activityEnvelope(testActivityRequest{OrganizationID: "input-org", Name: testWalletName})
	require.NoError(t, err)

	assert.Equal(t, "input-org", env["organizationId"])

	params, ok := env["parameters"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, testWalletName, params["name"])
}

func TestActivityEnvelope_OrgFallback(t *testing.T) {
	c, err := NewClient(nil, "client-org", WithHTTPRetries(0))
	require.NoError(t, err)

	env, err := c.activityEnvelope(testActivityRequest{Name: testWalletName})
	require.NoError(t, err)

	assert.Equal(t, "client-org", env["organizationId"])
}

func TestActivityEnvelope_MissingOrgReturnsError(t *testing.T) {
	c, err := NewClient(nil, "", WithHTTPRetries(0))
	require.NoError(t, err)

	_, err = c.activityEnvelope(testActivityRequest{Name: testWalletName})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organizationId is required")
}

func TestActivityEnvelope_ParametersNotNested(t *testing.T) {
	c, err := NewClient(nil, "my-org", WithHTTPRetries(0))
	require.NoError(t, err)

	env, err := c.activityEnvelope(testActivityRequest{Name: testWalletName})
	require.NoError(t, err)

	params, ok := env["parameters"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, params, "organizationId")
	assert.NotContains(t, params, "timestampMs")
	assert.Equal(t, testWalletName, params["name"])
}

// Client tests
func TestNew_Defaults(t *testing.T) {
	c, err := NewClient(nil, "my-org")
	require.NoError(t, err)
	assert.Equal(t, "https://api.turnkey.com", c.config.urls.baseURL)
	assert.Equal(t, "https://api.turnkey.com", c.BaseURL())
	assert.Equal(t, "https://authproxy.turnkey.com", c.AuthProxyBaseURL())
	assert.Equal(t, DefaultClientVersion, c.ClientVersion())
	assert.Equal(t, 3, c.config.http.maxRetries)
	assert.Equal(t, time.Second, c.config.activityPoll.interval)
	assert.Equal(t, 2*time.Minute, c.config.activityPoll.timeout)
	assert.Equal(t, 100*time.Millisecond, c.config.http.retryDelay)
}

func TestNew_WithMFAPollOptions(t *testing.T) {
	c, err := NewClient(
		nil,
		"my-org",
		WithActivityPollInterval(3*time.Second),
		WithActivityPollTimeout(4*time.Minute),
		WithMFAPolling(500*time.Millisecond, 30*time.Second),
	)
	require.NoError(t, err)

	assert.Equal(t, 3*time.Second, c.config.activityPoll.interval)
	assert.Equal(t, 4*time.Minute, c.config.activityPoll.timeout)
	assert.Equal(t, 500*time.Millisecond, c.config.mfaPoll.interval)
	assert.Equal(t, 30*time.Second, c.config.mfaPoll.timeout)
}

func TestNew_WithMFAPollingRejectsNonPositiveValues(t *testing.T) {
	_, err := NewClient(nil, "my-org", WithMFAPolling(0, time.Second))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MFA interval and timeout must both be > 0")
}

func TestNew_NegativeRetriesReturnsError(t *testing.T) {
	_, err := NewClient(nil, "my-org", WithHTTPRetries(-1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "httpMaxRetries must be >= 0")
}

func TestNew_WithBaseURLStripsTrailingSlash(t *testing.T) {
	c, err := NewClient(nil, "", WithBaseURL("https://api.turnkey.com/"))
	require.NoError(t, err)
	assert.Equal(t, "https://api.turnkey.com", c.config.urls.baseURL)
	assert.Equal(t, "https://api.turnkey.com", c.BaseURL())
}

func TestNew_WithAuthProxyBaseURLStripsTrailingSlash(t *testing.T) {
	c, err := NewClient(nil, "", WithAuthProxyBaseURL("https://authproxy.turnkey.com/"))
	require.NoError(t, err)
	assert.Equal(t, "https://authproxy.turnkey.com", c.AuthProxyBaseURL())
}

// PostJSON tests
func TestPostJSON_RetryBehavior(t *testing.T) {
	tests := []struct {
		name             string
		status           int
		expectedAttempts int
	}{
		{name: "RetriesOn5xx", status: http.StatusInternalServerError, expectedAttempts: 3}, // 1 initial + 2 retries
		{name: "NoRetryOn4xx", status: http.StatusBadRequest, expectedAttempts: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++

				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			c, err := NewClient(nil, "", WithBaseURL(server.URL), WithHTTPRetries(2), WithHTTPRetryDelay(0))
			require.NoError(t, err)

			err = c.postJSON(context.Background(), server.URL, "/test", nil, nil, false, nil)
			require.Error(t, err)
			assert.Equal(t, tt.expectedAttempts, attempts)
		})
	}
}

func TestPostJSON_SuccessOnRetry(t *testing.T) {
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"success": true}`))
			require.NoError(t, err)
		}
	}))
	defer server.Close()

	c, err := NewClient(nil, "", WithBaseURL(server.URL), WithHTTPRetries(3), WithHTTPRetryDelay(0))
	require.NoError(t, err)

	var result map[string]any

	err = c.postJSON(context.Background(), server.URL, "/test", nil, &result, false, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.Equal(t, true, result["success"])
}

// Error handling tests
func TestNewRequestError_WithMessage(t *testing.T) {
	body := []byte(`{"message": "something went wrong"}`)
	err := newRequestError(400, body)
	assert.Contains(t, err.Error(), "something went wrong")
	assert.Contains(t, err.Error(), "400")
}

func TestNewRequestError_InvalidJSON(t *testing.T) {
	body := []byte(`not json at all`)
	err := newRequestError(500, body)
	require.Error(t, err)

	var reqErr *RequestError
	require.ErrorAs(t, err, &reqErr)
	assert.Equal(t, 500, reqErr.StatusCode)
	assert.Nil(t, reqErr.Status)
}

// APIKeyStamper tests

func testPrivateKey(t *testing.T) string {
	t.Helper()

	apiKey, err := tkcrypto.NewAPIKey()
	require.NoError(t, err)

	return apiKey.GetPrivateKey()
}

func TestNewAPIKeyStamper_Valid(t *testing.T) {
	priv := testPrivateKey(t)
	stamper, err := NewAPIKeyStamper(priv)
	require.NoError(t, err)
	assert.NotNil(t, stamper)
}

func TestNewAPIKeyStamper_InvalidPrivateKey(t *testing.T) {
	_, err := NewAPIKeyStamper("not-a-valid-key")
	require.Error(t, err)
}

func TestNewClient_WithStamper(t *testing.T) {
	priv := testPrivateKey(t)
	stamper, err := NewAPIKeyStamper(priv)
	require.NoError(t, err)

	client, err := NewClient(stamper, "organization_id")
	require.NoError(t, err)
	assert.Equal(t, "organization_id", *client.DefaultOrganization())
}

func TestNewClient_WithStamperAndOptions(t *testing.T) {
	priv := testPrivateKey(t)
	stamper, err := NewAPIKeyStamper(priv)
	require.NoError(t, err)

	client, err := NewClient(
		stamper,
		"organization_id",
		WithBaseURL("https://custom.turnkey.com"),
		WithHTTPRetries(5),
	)
	require.NoError(t, err)
	assert.Equal(t, "https://custom.turnkey.com", client.config.urls.baseURL)
	assert.Equal(t, "https://custom.turnkey.com", client.BaseURL())
	assert.Equal(t, 5, client.config.http.maxRetries)
}
