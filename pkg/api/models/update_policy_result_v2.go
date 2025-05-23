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

// UpdatePolicyResultV2 update policy result v2
//
// swagger:model UpdatePolicyResultV2
type UpdatePolicyResultV2 struct {

	// Unique identifier for a given Policy.
	// Required: true
	PolicyID *string `json:"policyId"`
}

// Validate validates this update policy result v2
func (m *UpdatePolicyResultV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdatePolicyResultV2) validatePolicyID(formats strfmt.Registry) error {

	if err := validate.Required("policyId", "body", m.PolicyID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update policy result v2 based on context it is used
func (m *UpdatePolicyResultV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdatePolicyResultV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdatePolicyResultV2) UnmarshalBinary(b []byte) error {
	var res UpdatePolicyResultV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
