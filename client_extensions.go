package turnkey

import (
	"context"
	"encoding/json"
	"errors"
)

// SendSignedRequest sends a POST request with a signed body and decodes the response into T.
// For activity requests, it polls until the activity reaches a terminal status before decoding.
func SendSignedRequest[T any](ctx context.Context, c *Client, sr *SignedRequest) (*T, error) {
	if sr.Stamp == nil {
		return nil, errors.New("SignedRequest requires a Stamp")
	}

	respBody, err := c.postWithRetry(ctx, sr.URL, "", []byte(sr.Body), sr.Stamp, nil)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	if sr.Type == RequestTypeActivity {
		if err := c.resolveActivityInResponse(ctx, data); err != nil {
			return nil, err
		}
	}

	respBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var result T
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// resolveActivityInResponse re-marshals the "activity" field of a signed-request
// response, polls to terminal status if needed, and replaces it in data.
func (c *Client) resolveActivityInResponse(ctx context.Context, data map[string]any) error {
	activityData, ok := data["activity"].(map[string]any)
	if !ok {
		return nil
	}

	activityBytes, err := json.Marshal(activityData)
	if err != nil {
		return err
	}

	var activity Activity
	if err := json.Unmarshal(activityBytes, &activity); err != nil {
		return err
	}

	if _, done, err := classifyActivity(&activity); err != nil {
		return err
	} else if done {
		return nil
	}

	final, err := c.waitActivity(ctx, activity.ID)
	if err != nil {
		return err
	}

	data["activity"] = final

	return nil
}
