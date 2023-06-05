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

// V1CreatePrivateKeyTagIntent v1 create private key tag intent
//
// swagger:model v1CreatePrivateKeyTagIntent
type V1CreatePrivateKeyTagIntent struct {

	// @inject_tag: validate:"dive,uuid"
	//
	// A list of Private Key IDs.
	// Required: true
	PrivateKeyIds []string `json:"privateKeyIds"`

	// @inject_tag: validate:"required,tk_label,tk_label_length"
	//
	// Human-readable name for a Private Key Tag.
	// Required: true
	PrivateKeyTagName *string `json:"privateKeyTagName"`
}

// Validate validates this v1 create private key tag intent
func (m *V1CreatePrivateKeyTagIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePrivateKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyTagName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1CreatePrivateKeyTagIntent) validatePrivateKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyIds", "body", m.PrivateKeyIds); err != nil {
		return err
	}

	return nil
}

func (m *V1CreatePrivateKeyTagIntent) validatePrivateKeyTagName(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyTagName", "body", m.PrivateKeyTagName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this v1 create private key tag intent based on context it is used
func (m *V1CreatePrivateKeyTagIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1CreatePrivateKeyTagIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1CreatePrivateKeyTagIntent) UnmarshalBinary(b []byte) error {
	var res V1CreatePrivateKeyTagIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
