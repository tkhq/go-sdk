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

// V1CreatePolicyIntentV3 v1 create policy intent v3
//
// swagger:model v1CreatePolicyIntentV3
type V1CreatePolicyIntentV3 struct {

	// The condition expression that triggers the Effect
	Condition string `json:"condition,omitempty"`

	// The consensus expression that triggers the Effect
	Consensus string `json:"consensus,omitempty"`

	// The instruction to DENY or ALLOW an activity.
	// Required: true
	Effect *Immutableactivityv1Effect `json:"effect"`

	// notes
	Notes string `json:"notes,omitempty"`

	// Human-readable name for a Policy.
	// Required: true
	PolicyName *string `json:"policyName"`
}

// Validate validates this v1 create policy intent v3
func (m *V1CreatePolicyIntentV3) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEffect(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1CreatePolicyIntentV3) validateEffect(formats strfmt.Registry) error {

	if err := validate.Required("effect", "body", m.Effect); err != nil {
		return err
	}

	if err := validate.Required("effect", "body", m.Effect); err != nil {
		return err
	}

	if m.Effect != nil {
		if err := m.Effect.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("effect")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("effect")
			}
			return err
		}
	}

	return nil
}

func (m *V1CreatePolicyIntentV3) validatePolicyName(formats strfmt.Registry) error {

	if err := validate.Required("policyName", "body", m.PolicyName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this v1 create policy intent v3 based on the context it is used
func (m *V1CreatePolicyIntentV3) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEffect(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1CreatePolicyIntentV3) contextValidateEffect(ctx context.Context, formats strfmt.Registry) error {

	if m.Effect != nil {
		if err := m.Effect.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("effect")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("effect")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1CreatePolicyIntentV3) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1CreatePolicyIntentV3) UnmarshalBinary(b []byte) error {
	var res V1CreatePolicyIntentV3
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
