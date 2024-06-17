// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// CredentialType credential type
//
// swagger:model CredentialType
type CredentialType string

func NewCredentialType(value CredentialType) *CredentialType {
	return &value
}

// Pointer returns a pointer to a freshly-allocated CredentialType.
func (m CredentialType) Pointer() *CredentialType {
	return &m
}

const (

	// CREDENTIALTYPEWEBAUTHNAUTHENTICATOR captures enum value "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"
	CREDENTIALTYPEWEBAUTHNAUTHENTICATOR CredentialType = "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"

	// CREDENTIALTYPEAPIKEYP256 captures enum value "CREDENTIAL_TYPE_API_KEY_P256"
	CREDENTIALTYPEAPIKEYP256 CredentialType = "CREDENTIAL_TYPE_API_KEY_P256"

	// CREDENTIALTYPERECOVERUSERKEYP256 captures enum value "CREDENTIAL_TYPE_RECOVER_USER_KEY_P256"
	CREDENTIALTYPERECOVERUSERKEYP256 CredentialType = "CREDENTIAL_TYPE_RECOVER_USER_KEY_P256"
)

// for schema
var CredentialTypeEnum []CredentialType

func init() {
	var res []CredentialType
	if err := json.Unmarshal([]byte(`["CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR","CREDENTIAL_TYPE_API_KEY_P256","CREDENTIAL_TYPE_RECOVER_USER_KEY_P256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		CredentialTypeEnum = append(CredentialTypeEnum, v)
	}
}

func (m CredentialType) validateCredentialTypeEnum(path, location string, value CredentialType) error {
	if err := validate.EnumCase(path, location, value, CredentialTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this credential type
func (m CredentialType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateCredentialTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this credential type based on context it is used
func (m CredentialType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
