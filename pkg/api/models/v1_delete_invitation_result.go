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

// V1DeleteInvitationResult v1 delete invitation result
//
// swagger:model v1DeleteInvitationResult
type V1DeleteInvitationResult struct {

	// Unique identifier for a given Invitation.
	// Required: true
	InvitationID *string `json:"invitationId"`
}

// Validate validates this v1 delete invitation result
func (m *V1DeleteInvitationResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateInvitationID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1DeleteInvitationResult) validateInvitationID(formats strfmt.Registry) error {

	if err := validate.Required("invitationId", "body", m.InvitationID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this v1 delete invitation result based on context it is used
func (m *V1DeleteInvitationResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1DeleteInvitationResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1DeleteInvitationResult) UnmarshalBinary(b []byte) error {
	var res V1DeleteInvitationResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
