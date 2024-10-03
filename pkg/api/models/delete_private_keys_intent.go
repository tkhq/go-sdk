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

// DeletePrivateKeysIntent delete private keys intent
//
// swagger:model DeletePrivateKeysIntent
type DeletePrivateKeysIntent struct {

	// Optional parameter for deleting the private keys, even if any have not been previously exported. If they have been exported, this field is ignored.
	DeleteWithoutExport bool `json:"deleteWithoutExport,omitempty"`

	// List of unique identifiers for private keys within an organization
	// Required: true
	PrivateKeyIds []string `json:"privateKeyIds"`
}

// Validate validates this delete private keys intent
func (m *DeletePrivateKeysIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePrivateKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeletePrivateKeysIntent) validatePrivateKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyIds", "body", m.PrivateKeyIds); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this delete private keys intent based on context it is used
func (m *DeletePrivateKeysIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeletePrivateKeysIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeletePrivateKeysIntent) UnmarshalBinary(b []byte) error {
	var res DeletePrivateKeysIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}