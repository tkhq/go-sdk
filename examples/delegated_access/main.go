// Package main demonstrates the delegated access setup.
// For details check our docs https://docs.turnkey.com/concepts/policies/delegated-access
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/tkhq/go-sdk/crypto"
	turnkey "github.com/tkhq/go-sdk/v2"
)

//nolint:gocyclo
func main() {
	ctx := context.Background()

	apiPrivateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	if apiPrivateKey == "" {
		log.Fatal("TURNKEY_API_PRIVATE_KEY is required")
	}
	organizationID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	if organizationID == "" {
		log.Fatal("TURNKEY_ORGANIZATION_ID is required")
	}
	delegatedUserEmail := os.Getenv("TURNKEY_DELEGATED_USER_EMAIL")
	if delegatedUserEmail == "" {
		log.Fatal("TURNKEY_DELEGATED_USER_EMAIL is required")
	}
	endUserEmail := os.Getenv("TURNKEY_END_USER_EMAIL")
	if endUserEmail == "" {
		log.Fatal("TURNKEY_END_USER_EMAIL is required")
	}
	recipientAddress := os.Getenv("TURNKEY_RECIPIENT_ADDRESS")
	if recipientAddress == "" {
		log.Fatal("TURNKEY_RECIPIENT_ADDRESS is required")
	}

	stamper, err := turnkey.NewAPIKeyStamper(apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("generating delegated API key:", err)
	}
	delegatedPrivateKey := crypto.EncodePrivateECDSAKey(privKey)
	delegatedPublicKey := crypto.EncodePublicECDSAKey(&privKey.PublicKey)

	fmt.Println("P-256 Private:", delegatedPrivateKey)
	fmt.Println("P-256 Public:", delegatedPublicKey)

	createSubOrganizationResult, err := client.CreateSubOrganization(ctx, turnkey.CreateSubOrganizationRequest{
		OrganizationID:      organizationID,
		SubOrganizationName: "Sub Org - With Delegated",
		RootQuorumThreshold: 1,
		VerificationToken:   nil,
		ClientSignature:     nil,
		RootUsers: []turnkey.RootUserParamsV5{
			{
				UserName:  "Delegated User",
				UserEmail: &delegatedUserEmail,
				APIKeys: []turnkey.APIKeyParamsV2{
					{
						APIKeyName: "Delegated - API Key",
						CurveType:  turnkey.APIKeyCurveP256,
						PublicKey:  delegatedPublicKey,
					},
				},
				Authenticators: []turnkey.AuthenticatorParamsV2{},
				OAuthProviders: []turnkey.OAuthProviderParamsV2{},
			},
			{
				UserName:       "End User",
				UserEmail:      &endUserEmail,
				APIKeys:        []turnkey.APIKeyParamsV2{},
				Authenticators: []turnkey.AuthenticatorParamsV2{},
				OAuthProviders: []turnkey.OAuthProviderParamsV2{},
			},
		},
		Wallet: &turnkey.WalletParams{
			WalletName: "Default ETH Wallet",
			Accounts: []turnkey.WalletAccountParams{
				{
					AddressFormat: turnkey.AddressFormatEthereum,
					Curve:         turnkey.CurveSecp256K1,
					Path:          "m/44'/60'/0'/0/0",
					PathFormat:    turnkey.PathFormatBip32,
				},
			},
		},
	})
	if err != nil {
		log.Fatal("create sub-organization failed:", err)
	}
	if len(createSubOrganizationResult.RootUserIds) < 2 {
		log.Fatalf("create sub-organization result included %d root user id(s), expected 2", len(createSubOrganizationResult.RootUserIds))
	}

	subOrganizationID := createSubOrganizationResult.SubOrganizationID
	fmt.Printf("Sub-organization id: %s\n", subOrganizationID)

	delegatedStamper, err := turnkey.NewAPIKeyStamper(delegatedPrivateKey)
	if err != nil {
		log.Fatal("failed to create delegated stamper:", err)
	}

	delegatedClient, err := turnkey.NewClient(delegatedStamper, subOrganizationID)
	if err != nil {
		log.Fatal("failed to create delegated SDK client:", err)
	}

	delegatedUserID := createSubOrganizationResult.RootUserIds[0]
	endUserID := createSubOrganizationResult.RootUserIds[1]

	createPolicyResult, err := delegatedClient.CreatePolicy(ctx, turnkey.CreatePolicyRequest{
		OrganizationID: subOrganizationID,
		PolicyName:     "Allow Delegated Account to sign transactions to specific address",
		Effect:         turnkey.EffectAllow,
		Condition:      ptr(fmt.Sprintf("eth.tx.to == '%s'", recipientAddress)),
		Consensus:      ptr(fmt.Sprintf("approvers.any(user, user.id == '%s')", delegatedUserID)),
		Notes:          "Policy notes",
	})
	if err != nil {
		log.Fatal("create policy failed:", err)
	}
	fmt.Printf("New policy created: %s\n", createPolicyResult.PolicyID)

	if _, err := delegatedClient.UpdateRootQuorum(ctx, turnkey.UpdateRootQuorumRequest{
		OrganizationID: subOrganizationID,
		UserIds:        []string{endUserID},
		Threshold:      1,
	}); err != nil {
		log.Fatal("update root quorum failed:", err)
	}
	fmt.Println("Root quorum updated")
}

func ptr[T any](value T) *T {
	return &value
}
