// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// V1AuthenticatorParams v1 authenticator params
//
// swagger:model v1AuthenticatorParams
type V1AuthenticatorParams struct {

	// attestation
	// Required: true
	Attestation *V1PublicKeyCredentialWithAttestation `json:"attestation"`

	// Human-readable name for an Authenticator.
	// Required: true
	AuthenticatorName *string `json:"authenticatorName"`

	// Challenge presented for authentication purposes.
	// Required: true
	Challenge *string `json:"challenge"`

	// Unique identifier for a given User.
	// Required: true
	UserID *string `json:"userId"`
}

// Validate validates this v1 authenticator params
func (m *V1AuthenticatorParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttestation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticatorName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateChallenge(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1AuthenticatorParams) validateAttestation(formats strfmt.Registry) error {

	if err := validate.Required("attestation", "body", m.Attestation); err != nil {
		return err
	}

	if m.Attestation != nil {
		if err := m.Attestation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attestation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attestation")
			}
			return err
		}
	}

	return nil
}

func (m *V1AuthenticatorParams) validateAuthenticatorName(formats strfmt.Registry) error {

	if err := validate.Required("authenticatorName", "body", m.AuthenticatorName); err != nil {
		return err
	}

	return nil
}

func (m *V1AuthenticatorParams) validateChallenge(formats strfmt.Registry) error {

	if err := validate.Required("challenge", "body", m.Challenge); err != nil {
		return err
	}

	return nil
}

func (m *V1AuthenticatorParams) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this v1 authenticator params based on the context it is used
func (m *V1AuthenticatorParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttestation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1AuthenticatorParams) contextValidateAttestation(ctx context.Context, formats strfmt.Registry) error {

	if m.Attestation != nil {

		if err := m.Attestation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("attestation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("attestation")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1AuthenticatorParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1AuthenticatorParams) UnmarshalBinary(b []byte) error {
	var res V1AuthenticatorParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
