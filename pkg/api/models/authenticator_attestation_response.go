// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// AuthenticatorAttestationResponse authenticator attestation response
//
// swagger:model AuthenticatorAttestationResponse
type AuthenticatorAttestationResponse struct {

	// attestation object
	// Required: true
	AttestationObject *string `json:"attestationObject"`

	// authenticator attachment
	// Enum: ["cross-platform","platform"]
	AuthenticatorAttachment *string `json:"authenticatorAttachment,omitempty"`

	// client data Json
	// Required: true
	ClientDataJSON *string `json:"clientDataJson"`

	// transports
	Transports []AuthenticatorTransport `json:"transports"`
}

// Validate validates this authenticator attestation response
func (m *AuthenticatorAttestationResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttestationObject(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticatorAttachment(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientDataJSON(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransports(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthenticatorAttestationResponse) validateAttestationObject(formats strfmt.Registry) error {

	if err := validate.Required("attestationObject", "body", m.AttestationObject); err != nil {
		return err
	}

	return nil
}

var authenticatorAttestationResponseTypeAuthenticatorAttachmentPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["cross-platform","platform"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		authenticatorAttestationResponseTypeAuthenticatorAttachmentPropEnum = append(authenticatorAttestationResponseTypeAuthenticatorAttachmentPropEnum, v)
	}
}

const (

	// AuthenticatorAttestationResponseAuthenticatorAttachmentCrossDashPlatform captures enum value "cross-platform"
	AuthenticatorAttestationResponseAuthenticatorAttachmentCrossDashPlatform string = "cross-platform"

	// AuthenticatorAttestationResponseAuthenticatorAttachmentPlatform captures enum value "platform"
	AuthenticatorAttestationResponseAuthenticatorAttachmentPlatform string = "platform"
)

// prop value enum
func (m *AuthenticatorAttestationResponse) validateAuthenticatorAttachmentEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, authenticatorAttestationResponseTypeAuthenticatorAttachmentPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AuthenticatorAttestationResponse) validateAuthenticatorAttachment(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticatorAttachment) { // not required
		return nil
	}

	// value enum
	if err := m.validateAuthenticatorAttachmentEnum("authenticatorAttachment", "body", *m.AuthenticatorAttachment); err != nil {
		return err
	}

	return nil
}

func (m *AuthenticatorAttestationResponse) validateClientDataJSON(formats strfmt.Registry) error {

	if err := validate.Required("clientDataJson", "body", m.ClientDataJSON); err != nil {
		return err
	}

	return nil
}

func (m *AuthenticatorAttestationResponse) validateTransports(formats strfmt.Registry) error {
	if swag.IsZero(m.Transports) { // not required
		return nil
	}

	for i := 0; i < len(m.Transports); i++ {

		if err := m.Transports[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transports" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transports" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// ContextValidate validate this authenticator attestation response based on the context it is used
func (m *AuthenticatorAttestationResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTransports(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthenticatorAttestationResponse) contextValidateTransports(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Transports); i++ {

		if swag.IsZero(m.Transports[i]) { // not required
			return nil
		}

		if err := m.Transports[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transports" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("transports" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuthenticatorAttestationResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthenticatorAttestationResponse) UnmarshalBinary(b []byte) error {
	var res AuthenticatorAttestationResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
