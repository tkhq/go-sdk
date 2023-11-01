// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// CreatePrivateKeysIntent create private keys intent
//
// swagger:model CreatePrivateKeysIntent
type CreatePrivateKeysIntent struct {

	// A list of Private Keys.
	// Required: true
	PrivateKeys []*PrivateKeyParams `json:"privateKeys"`
}

// Validate validates this create private keys intent
func (m *CreatePrivateKeysIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePrivateKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreatePrivateKeysIntent) validatePrivateKeys(formats strfmt.Registry) error {

	if err := validate.Required("privateKeys", "body", m.PrivateKeys); err != nil {
		return err
	}

	for i := 0; i < len(m.PrivateKeys); i++ {
		if swag.IsZero(m.PrivateKeys[i]) { // not required
			continue
		}

		if m.PrivateKeys[i] != nil {
			if err := m.PrivateKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this create private keys intent based on the context it is used
func (m *CreatePrivateKeysIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePrivateKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreatePrivateKeysIntent) contextValidatePrivateKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.PrivateKeys); i++ {

		if m.PrivateKeys[i] != nil {

			if swag.IsZero(m.PrivateKeys[i]) { // not required
				return nil
			}

			if err := m.PrivateKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *CreatePrivateKeysIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreatePrivateKeysIntent) UnmarshalBinary(b []byte) error {
	var res CreatePrivateKeysIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}