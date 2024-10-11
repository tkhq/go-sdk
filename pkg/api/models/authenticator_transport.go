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

// AuthenticatorTransport authenticator transport
//
// swagger:model AuthenticatorTransport
type AuthenticatorTransport string

func NewAuthenticatorTransport(value AuthenticatorTransport) *AuthenticatorTransport {
	return &value
}

// Pointer returns a pointer to a freshly-allocated AuthenticatorTransport.
func (m AuthenticatorTransport) Pointer() *AuthenticatorTransport {
	return &m
}

const (

	// AUTHENTICATORTRANSPORTBLE captures enum value "AUTHENTICATOR_TRANSPORT_BLE"
	AUTHENTICATORTRANSPORTBLE AuthenticatorTransport = "AUTHENTICATOR_TRANSPORT_BLE"

	// AUTHENTICATORTRANSPORTINTERNAL captures enum value "AUTHENTICATOR_TRANSPORT_INTERNAL"
	AUTHENTICATORTRANSPORTINTERNAL AuthenticatorTransport = "AUTHENTICATOR_TRANSPORT_INTERNAL"

	// AUTHENTICATORTRANSPORTNFC captures enum value "AUTHENTICATOR_TRANSPORT_NFC"
	AUTHENTICATORTRANSPORTNFC AuthenticatorTransport = "AUTHENTICATOR_TRANSPORT_NFC"

	// AUTHENTICATORTRANSPORTUSB captures enum value "AUTHENTICATOR_TRANSPORT_USB"
	AUTHENTICATORTRANSPORTUSB AuthenticatorTransport = "AUTHENTICATOR_TRANSPORT_USB"

	// AUTHENTICATORTRANSPORTHYBRID captures enum value "AUTHENTICATOR_TRANSPORT_HYBRID"
	AUTHENTICATORTRANSPORTHYBRID AuthenticatorTransport = "AUTHENTICATOR_TRANSPORT_HYBRID"
)

// for schema
var AuthenticatorTransportEnum []AuthenticatorTransport

func init() {
	var res []AuthenticatorTransport
	if err := json.Unmarshal([]byte(`["AUTHENTICATOR_TRANSPORT_BLE","AUTHENTICATOR_TRANSPORT_INTERNAL","AUTHENTICATOR_TRANSPORT_NFC","AUTHENTICATOR_TRANSPORT_USB","AUTHENTICATOR_TRANSPORT_HYBRID"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		AuthenticatorTransportEnum = append(AuthenticatorTransportEnum, v)
	}
}

func (m AuthenticatorTransport) validateAuthenticatorTransportEnum(path, location string, value AuthenticatorTransport) error {
	if err := validate.EnumCase(path, location, value, AuthenticatorTransportEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this authenticator transport
func (m AuthenticatorTransport) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateAuthenticatorTransportEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this authenticator transport based on context it is used
func (m AuthenticatorTransport) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
