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

// DeletePrivateKeysResult delete private keys result
//
// swagger:model DeletePrivateKeysResult
type DeletePrivateKeysResult struct {

	// A list of private key unique identifiers that were removed
	// Required: true
	PrivateKeyIds []string `json:"privateKeyIds"`
}

// Validate validates this delete private keys result
func (m *DeletePrivateKeysResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePrivateKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeletePrivateKeysResult) validatePrivateKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyIds", "body", m.PrivateKeyIds); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this delete private keys result based on context it is used
func (m *DeletePrivateKeysResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeletePrivateKeysResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeletePrivateKeysResult) UnmarshalBinary(b []byte) error {
	var res DeletePrivateKeysResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
