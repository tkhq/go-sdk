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

// Policy policy
//
// swagger:model Policy
type Policy struct {

	// A condition expression that evalutes to true or false.
	// Required: true
	Condition *string `json:"condition"`

	// A consensus expression that evalutes to true or false.
	// Required: true
	Consensus *string `json:"consensus"`

	// created at
	// Required: true
	CreatedAt *ExternalDataV1Timestamp `json:"createdAt"`

	// The instruction to DENY or ALLOW a particular activity following policy selector(s).
	// Required: true
	Effect *Effect `json:"effect"`

	// Human-readable notes added by a User to describe a particular policy.
	// Required: true
	Notes *string `json:"notes"`

	// Unique identifier for a given Policy.
	// Required: true
	PolicyID *string `json:"policyId"`

	// Human-readable name for a Policy.
	// Required: true
	PolicyName *string `json:"policyName"`

	// updated at
	// Required: true
	UpdatedAt *ExternalDataV1Timestamp `json:"updatedAt"`
}

// Validate validates this policy
func (m *Policy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCondition(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConsensus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEffect(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNotes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Policy) validateCondition(formats strfmt.Registry) error {

	if err := validate.Required("condition", "body", m.Condition); err != nil {
		return err
	}

	return nil
}

func (m *Policy) validateConsensus(formats strfmt.Registry) error {

	if err := validate.Required("consensus", "body", m.Consensus); err != nil {
		return err
	}

	return nil
}

func (m *Policy) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("createdAt", "body", m.CreatedAt); err != nil {
		return err
	}

	if m.CreatedAt != nil {
		if err := m.CreatedAt.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("createdAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("createdAt")
			}
			return err
		}
	}

	return nil
}

func (m *Policy) validateEffect(formats strfmt.Registry) error {

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

func (m *Policy) validateNotes(formats strfmt.Registry) error {

	if err := validate.Required("notes", "body", m.Notes); err != nil {
		return err
	}

	return nil
}

func (m *Policy) validatePolicyID(formats strfmt.Registry) error {

	if err := validate.Required("policyId", "body", m.PolicyID); err != nil {
		return err
	}

	return nil
}

func (m *Policy) validatePolicyName(formats strfmt.Registry) error {

	if err := validate.Required("policyName", "body", m.PolicyName); err != nil {
		return err
	}

	return nil
}

func (m *Policy) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updatedAt", "body", m.UpdatedAt); err != nil {
		return err
	}

	if m.UpdatedAt != nil {
		if err := m.UpdatedAt.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("updatedAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("updatedAt")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this policy based on the context it is used
func (m *Policy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreatedAt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEffect(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUpdatedAt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Policy) contextValidateCreatedAt(ctx context.Context, formats strfmt.Registry) error {

	if m.CreatedAt != nil {

		if err := m.CreatedAt.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("createdAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("createdAt")
			}
			return err
		}
	}

	return nil
}

func (m *Policy) contextValidateEffect(ctx context.Context, formats strfmt.Registry) error {

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

func (m *Policy) contextValidateUpdatedAt(ctx context.Context, formats strfmt.Registry) error {

	if m.UpdatedAt != nil {

		if err := m.UpdatedAt.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("updatedAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("updatedAt")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Policy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Policy) UnmarshalBinary(b []byte) error {
	var res Policy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
