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

// DeleteSubOrganizationResult delete sub organization result
//
// swagger:model DeleteSubOrganizationResult
type DeleteSubOrganizationResult struct {

	// Unique identifier of the sub organization that was removed
	// Required: true
	SubOrganizationUUID *string `json:"subOrganizationUuid"`
}

// Validate validates this delete sub organization result
func (m *DeleteSubOrganizationResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSubOrganizationUUID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeleteSubOrganizationResult) validateSubOrganizationUUID(formats strfmt.Registry) error {

	if err := validate.Required("subOrganizationUuid", "body", m.SubOrganizationUUID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this delete sub organization result based on context it is used
func (m *DeleteSubOrganizationResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeleteSubOrganizationResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeleteSubOrganizationResult) UnmarshalBinary(b []byte) error {
	var res DeleteSubOrganizationResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
