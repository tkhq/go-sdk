// Package main demonstrates the delegated access setup
// For details check our docs https://docs.turnkey.com/concepts/policies/delegated-access
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/organizations"
	"github.com/tkhq/go-sdk/pkg/api/client/policies"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

func main() {

	// Parent organization API key used by the client to create the sub-organization
	apiKey, err := apikey.FromTurnkeyPrivateKey("<private_key_here>", apikey.SchemeP256)
	if err != nil {
		log.Fatal("creating API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	// Generate a new API keypair for the delegated user account
	// If you genarate the keys outside of this script just assign them to delegatedPrivateKey and delegatedPublicKey variables
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Private key bytes (32 bytes, padded if needed)
	privBytes := privKey.D.Bytes()
	if len(privBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privBytes):], privBytes)
		privBytes = padded
	}

	// Public key bytes (compressed form: 0x02 or 0x03 + X)
	pubKey := compressPubkey(&privKey.PublicKey)

	// Output in hex
	fmt.Println("🔑 P-256 Private:", hex.EncodeToString(privBytes))
	fmt.Println("🔓 P-256 Public:", hex.EncodeToString(pubKey))

	//API keypair used by the delegated user
	delegatedPrivateKey := hex.EncodeToString(privBytes)
	delegatedPublicKey := hex.EncodeToString(pubKey)

	var quorumThreshold int32 = 1

	createSubOrganizationParams := organizations.NewCreateSubOrganizationParams().WithBody(&models.CreateSubOrganizationRequest{
		OrganizationID: StringPointer("<parent_org_id>"), // parent organization id
		Parameters: &models.CreateSubOrganizationIntentV7{
			SubOrganizationName: StringPointer("Sub Org - With Delegated"),
			RootUsers: []*models.RootUserParamsV4{
				{
					UserName:  StringPointer("Delegated User"),
					UserEmail: *StringPointer("<email_address>"),
					APIKeys: []*models.APIKeyParamsV2{
						{
							APIKeyName: StringPointer("Delegated - API Key"),
							CurveType:  models.APIKeyCurveP256.Pointer(),
							PublicKey:  &delegatedPublicKey,
						},
					},
					Authenticators: []*models.AuthenticatorParamsV2{},
					OauthProviders: []*models.OauthProviderParams{},
				},
				{
					UserName:       StringPointer("End User"),
					UserEmail:      *StringPointer("<email_address>"),
					APIKeys:        []*models.APIKeyParamsV2{},
					Authenticators: []*models.AuthenticatorParamsV2{},
					OauthProviders: []*models.OauthProviderParams{},
				},
			},
			RootQuorumThreshold: &quorumThreshold,
			Wallet: &models.WalletParams{
				WalletName: StringPointer("Default ETH Wallet"),
				Accounts: []*models.WalletAccountParams{
					{
						AddressFormat: models.AddressFormatEthereum.Pointer(),
						Curve:         models.CurveSecp256k1.Pointer(),
						Path:          StringPointer("m/44'/60'/0'/0/0"),
						PathFormat:    models.PathFormatBip32.Pointer(),
					},
				},
			},
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        StringPointer(string(models.ActivityTypeCreateSubOrganizationV7)),
	})

	resp, err := client.V0().Organizations.CreateSubOrganization(createSubOrganizationParams, client.Authenticator)
	if err != nil {
		log.Fatal("Create sub-organization request failed:", err)
	}

	fmt.Printf("Sub-organization id : %v\n", *resp.Payload.Activity.Result.CreateSubOrganizationResultV7.SubOrganizationID)
	subOrganizationId := *resp.Payload.Activity.Result.CreateSubOrganizationResultV7.SubOrganizationID

	// Initializing a new Turnkey client used by the Delegated account activities
	// Notice the subOrganizationId created above
	delegatedApiKey, err := apikey.FromTurnkeyPrivateKey(delegatedPrivateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatal("creating API key: %w", err)
	}

	delegatedClient, err := sdk.New(sdk.WithAPIKey(delegatedApiKey))
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	// Creating a policy for the Delegated account
	delegatedUserId := resp.Payload.Activity.Result.CreateSubOrganizationResultV7.RootUserIds[0]
	endUserId := resp.Payload.Activity.Result.CreateSubOrganizationResultV7.RootUserIds[1]

	recipientAddress := "<ethereum_address>"

	createPolicyParams := policies.NewCreatePolicyParams().WithBody(&models.CreatePolicyRequest{
		OrganizationID: &subOrganizationId,
		TimestampMs:    util.RequestTimestamp(),
		Type:           (*string)(models.ActivityTypeCreatePolicyV3.Pointer()),
		Parameters: &models.CreatePolicyIntentV3{
			PolicyName: StringPointer("Allow Delegated Account to sign transactions to specific address"),
			Effect:     models.EffectAllow.Pointer(),
			Condition:  fmt.Sprintf("eth.tx.to == '%s'", recipientAddress),
			Consensus:  fmt.Sprintf("approvers.any(user, user.id == '%s')", delegatedUserId),
			Notes:      "Policy notes",
		},
	})

	createPolicyReply, err := client.V0().Policies.CreatePolicy(createPolicyParams, delegatedClient.Authenticator)
	if err != nil {
		log.Fatal("Create policy request failed:", err)
	}

	fmt.Printf("New policy created!: %v\n", *createPolicyReply.Payload.Activity.Result.CreatePolicyResult.PolicyID)

	// Remove the Delegated user from the root quorum
	updateRootQuorumParams := organizations.NewUpdateRootQuorumParams()
	updateRootQuorumParams.SetBody(&models.UpdateRootQuorumRequest{
		OrganizationID: &subOrganizationId,
		Parameters: &models.UpdateRootQuorumIntent{
			UserIds:   []string{endUserId}, // Update to 1/1: only the end user is root
			Threshold: &quorumThreshold,
		},
		TimestampMs: util.RequestTimestamp(),
		Type:        StringPointer(string(models.ActivityTypeUpdateRootQuorum)),
	})

	updateRootQuorumReply, err := client.V0().Organizations.UpdateRootQuorum(updateRootQuorumParams, delegatedClient.Authenticator)
	if err != nil {
		log.Fatal("Update root quorum request failed:", err)
	}
	fmt.Printf("Root Quorum updated! : %v\n", *updateRootQuorumReply.Payload.Activity.Status)

}

// StringPointer returns a pointer to a string
func StringPointer(s string) *string {
	return &s
}

// compressPubkey takes an *ecdsa.PublicKey and returns the compressed form
func compressPubkey(pub *ecdsa.PublicKey) []byte {
	x := pub.X.Bytes()
	if len(x) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(x):], x)
		x = padded
	}
	prefix := byte(0x02)
	if pub.Y.Bit(0) == 1 {
		prefix = 0x03
	}
	return append([]byte{prefix}, x...)
}
