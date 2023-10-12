package cosmos

import (
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/tkhq/go-sdk"
	turnkeyClient "github.com/tkhq/go-sdk/pkg/api/client"
	"github.com/tkhq/go-sdk/pkg/api/client/activities"
	"github.com/tkhq/go-sdk/pkg/api/client/private_keys"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

type turnkeySigner struct {
	turnkeyClient  turnkeyClient.TurnkeyPublicAPI
	organizationID string
	apiHost        string
	apiKey         *apikey.Key
}

type SignerParams struct {
	TurnkeyClient  turnkeyClient.TurnkeyPublicAPI
	OrganizationID string
	ApiHost        string
	ApiKey         *apikey.Key
}

func NewSigner(params SignerParams) *turnkeySigner {
	return &turnkeySigner{
		organizationID: params.OrganizationID,
		turnkeyClient:  params.TurnkeyClient,
		apiHost:        params.ApiHost,
		apiKey:         params.ApiKey,
	}
}

func (s *turnkeySigner) Sign(uid string, msg []byte) ([]byte, error) {
	hexMsg := hex.EncodeToString(msg)
	timestamp := util.RequestTimestamp()

	p := private_keys.NewPublicAPIServiceSignRawPayloadParams().WithBody(&models.V1SignRawPayloadRequest{
		OrganizationID: &s.organizationID,
		Parameters: &models.V1SignRawPayloadIntent{
			PrivateKeyID: &uid,
			Payload:      &hexMsg,
			Encoding:     models.Immutableactivityv1PayloadEncodingPAYLOADENCODINGHEXADECIMAL.Pointer(),
			HashFunction: models.Immutableactivityv1HashFunctionHASHFUNCTIONSHA256.Pointer(),
		},
		TimestampMs: timestamp,
		Type:        (*string)(models.V1ActivityTypeACTIVITYTYPESIGNRAWPAYLOAD.Pointer()),
	})

	activityResponse, err := s.turnkeyClient.PrivateKeys.PublicAPIServiceSignRawPayload(p, s.GetAuthenticator())
	if err != nil {
		return nil, err
	}

	result, err := s.waitForResult(*activityResponse.Payload.Activity.ID)
	if err != nil {
		return nil, err
	}

	rValue, err := hex.DecodeString(*result.SignRawPayloadResult.R)
	if err != nil {
		return nil, errors.Wrap(err, "decode R value error")
	}

	sValue, err := hex.DecodeString(*result.SignRawPayloadResult.S)
	if err != nil {
		return nil, errors.Wrap(err, "decode S value error")
	}

	return append(rValue, sValue...), nil
}

func (s *turnkeySigner) waitForResult(activityId string) (*models.V1Result, error) {
	time.Sleep(1 * time.Second)

	params := activities.NewPublicAPIServiceGetActivityParams().WithBody(&models.V1GetActivityRequest{
		ActivityID:     func() *string { return &activityId }(),
		OrganizationID: &s.organizationID,
	})
	resp, err := s.turnkeyClient.Activities.PublicAPIServiceGetActivity(params, s.GetAuthenticator())
	if err != nil {
		return nil, err
	}

	return resp.Payload.Activity.Result, nil
}

func (s *turnkeySigner) GetAuthenticator() *sdk.Authenticator {
	return &sdk.Authenticator{Key: s.apiKey}
}
