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

// V1SignTransactionIntentV2 v1 sign transaction intent v2
//
// swagger:model v1SignTransactionIntentV2
type V1SignTransactionIntentV2 struct {

	// The Private Key identifier or address.
	// Required: true
	SignWith *string `json:"signWith"`

	// type
	// Required: true
	Type *V1TransactionType `json:"type"`

	// Raw unsigned transaction to be signed
	// Required: true
	UnsignedTransaction *string `json:"unsignedTransaction"`
}

// Validate validates this v1 sign transaction intent v2
func (m *V1SignTransactionIntentV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSignWith(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUnsignedTransaction(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1SignTransactionIntentV2) validateSignWith(formats strfmt.Registry) error {

	if err := validate.Required("signWith", "body", m.SignWith); err != nil {
		return err
	}

	return nil
}

func (m *V1SignTransactionIntentV2) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if m.Type != nil {
		if err := m.Type.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

func (m *V1SignTransactionIntentV2) validateUnsignedTransaction(formats strfmt.Registry) error {

	if err := validate.Required("unsignedTransaction", "body", m.UnsignedTransaction); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this v1 sign transaction intent v2 based on the context it is used
func (m *V1SignTransactionIntentV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1SignTransactionIntentV2) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if m.Type != nil {

		if err := m.Type.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1SignTransactionIntentV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1SignTransactionIntentV2) UnmarshalBinary(b []byte) error {
	var res V1SignTransactionIntentV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
