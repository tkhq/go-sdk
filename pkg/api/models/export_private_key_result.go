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

// ExportPrivateKeyResult export private key result
//
// swagger:model ExportPrivateKeyResult
type ExportPrivateKeyResult struct {

	// Export bundle containing a private key encrypted to the client's target public key.
	// Required: true
	ExportBundle *string `json:"exportBundle"`

	// Unique identifier for a given Private Key.
	// Required: true
	PrivateKeyID *string `json:"privateKeyId"`
}

// Validate validates this export private key result
func (m *ExportPrivateKeyResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExportBundle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ExportPrivateKeyResult) validateExportBundle(formats strfmt.Registry) error {

	if err := validate.Required("exportBundle", "body", m.ExportBundle); err != nil {
		return err
	}

	return nil
}

func (m *ExportPrivateKeyResult) validatePrivateKeyID(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyId", "body", m.PrivateKeyID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this export private key result based on context it is used
func (m *ExportPrivateKeyResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ExportPrivateKeyResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ExportPrivateKeyResult) UnmarshalBinary(b []byte) error {
	var res ExportPrivateKeyResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}