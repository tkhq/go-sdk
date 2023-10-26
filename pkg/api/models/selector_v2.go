// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SelectorV2 selector v2
//
// swagger:model SelectorV2
type SelectorV2 struct {

	// operator
	Operator ActivityV1Operator `json:"operator,omitempty"`

	// subject
	Subject string `json:"subject,omitempty"`

	// targets
	Targets []string `json:"targets"`
}

// Validate validates this selector v2
func (m *SelectorV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOperator(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelectorV2) validateOperator(formats strfmt.Registry) error {
	if swag.IsZero(m.Operator) { // not required
		return nil
	}

	if err := m.Operator.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("operator")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("operator")
		}
		return err
	}

	return nil
}

// ContextValidate validate this selector v2 based on the context it is used
func (m *SelectorV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOperator(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SelectorV2) contextValidateOperator(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Operator.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("operator")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("operator")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SelectorV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SelectorV2) UnmarshalBinary(b []byte) error {
	var res SelectorV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
