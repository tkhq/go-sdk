package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	bankv1beta1 "cosmossdk.io/api/cosmos/bank/v1beta1"
	basev1beta1 "cosmossdk.io/api/cosmos/base/v1beta1"
	cosmosSecp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	signingv1beta1 "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/cosmos/cosmos-proto/anyutil"
	"github.com/davecgh/go-spew/spew"
	tendermintClient "github.com/tendermint/tendermint/rpc/client/http"
	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client"
	"github.com/tkhq/go-sdk/pkg/api/client/private_keys"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/signer/cosmos"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func getPublicKey(turnkeyClient *client.TurnkeyPublicAPI, orgID string, privateKeyID string, apiKey *apikey.Key) ([]byte, error) {
	getSenderPrivateKeyRequest := private_keys.NewPublicAPIServiceGetPrivateKeyParams().WithBody(&models.V1GetPrivateKeyRequest{
		OrganizationID: &orgID,
		PrivateKeyID:   &privateKeyID,
	})

	getSenderPrivateKeyResponse, err := turnkeyClient.PrivateKeys.PublicAPIServiceGetPrivateKey(getSenderPrivateKeyRequest, &sdk.Authenticator{Key: apiKey})
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := hex.DecodeString(*getSenderPrivateKeyResponse.Payload.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return cosmos.CompressPublicKey(publicKeyBytes), nil
}

func main() {
	receiverPrivateKeyID := os.Getenv("RECEIVER_PRIVATE_KEY_ID")
	senderPrivateKeyID := os.Getenv("SENDER_PRIVATE_KEY_ID")
	apiPrivateKey := os.Getenv("API_PRIVATE_KEY")
	apiHost := os.Getenv("TURNKEY_BASE_URL")
	orgID := os.Getenv("ORGANIZATION_ID")

	ctx := context.Background()

	apiKey, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey)
	if err != nil {
		panic(err)
	}

	publicApiClient := client.NewHTTPClientWithConfig(nil, &client.TransportConfig{
		Host: apiHost,
	})

	signer := cosmos.NewSigner(cosmos.SignerParams{
		TurnkeyClient:  *publicApiClient,
		OrganizationID: orgID,
		ApiHost:        apiHost,
		ApiKey:         apiKey,
	})

	fromPublicKey, err := getPublicKey(publicApiClient, orgID, senderPrivateKeyID, apiKey)
	if err != nil {
		panic(err)
	}

	toPublicKey, err := getPublicKey(publicApiClient, orgID, receiverPrivateKeyID, apiKey)
	if err != nil {
		panic(err)
	}

	toAddress := cosmos.CosmosAddressFromPublicKey(toPublicKey)
	fromAddress := cosmos.CosmosAddressFromPublicKey(fromPublicKey)

	fmt.Println("Sending from: ")
	fmt.Println(fromAddress)
	fmt.Println("Sending to: ")
	fmt.Println(toAddress)

	pk, err := anyutil.New(&cosmosSecp.PubKey{Key: fromPublicKey})
	if err != nil {
		panic(err)
	}

	signerInfo := []*txv1beta1.SignerInfo{
		{
			PublicKey: pk,
			ModeInfo: &txv1beta1.ModeInfo{
				Sum: &txv1beta1.ModeInfo_Single_{
					Single: &txv1beta1.ModeInfo_Single{
						Mode: signingv1beta1.SignMode_SIGN_MODE_DIRECT,
					},
				},
			},
			Sequence: 2,
		},
	}

	fee := &txv1beta1.Fee{
		Amount: []*basev1beta1.Coin{
			{
				Denom:  "uatom",
				Amount: "1000",
			},
		},
		GasLimit: 200000,
	}

	msg, err := anyutil.New(&bankv1beta1.MsgSend{
		FromAddress: fromAddress,
		ToAddress:   toAddress,
		Amount: []*basev1beta1.Coin{
			{
				Denom:  "uatom",
				Amount: "1",
			},
		},
	})
	if err != nil {
		panic(err)
	}

	txBody := &txv1beta1.TxBody{
		Messages: []*anypb.Any{msg},
		Memo:     "Turnkey demo",
	}

	authInfo := &txv1beta1.AuthInfo{
		Fee:         fee,
		SignerInfos: signerInfo,
	}

	bodyBz, err := proto.Marshal(txBody)
	if err != nil {
		panic(err)
	}

	authInfoBz, err := proto.Marshal(authInfo)
	if err != nil {
		panic(err)
	}

	signBytes, err := proto.Marshal(&txv1beta1.SignDoc{
		BodyBytes:     bodyBz,
		AuthInfoBytes: authInfoBz,
		ChainId:       "cosmoshub-4",
		AccountNumber: 1878048,
	})
	if err != nil {
		panic(err)
	}

	c, err := tendermintClient.New("https://cosmos-rpc.publicnode.com:443")
	if err != nil {
		panic(err)
	}

	signature, err := signer.Sign(senderPrivateKeyID, signBytes)
	if err != nil {
		panic(err)
	}

	tx := txv1beta1.Tx{
		Body:     txBody,
		AuthInfo: authInfo,
		Signatures: [][]byte{
			signature,
		},
	}

	txBytes, err := proto.Marshal(&tx)
	if err != nil {
		panic(err)
	}

	result, err := c.BroadcastTxSync(ctx, txBytes)
	if err != nil {
		panic(err)
	}

	spew.Dump(result)
}
