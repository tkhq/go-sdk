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

// ExternalDataV1Quorum external data v1 quorum
//
// swagger:model external.data.v1.Quorum
type ExternalDataV1Quorum struct {

	// Count of unique approvals required to meet quorum.
	// Required: true
	Threshold *int32 `json:"threshold"`

	// Unique identifiers of quorum set members.
	// Required: true
	UserIds []string `json:"userIds"`
}

// Validate validates this external data v1 quorum
func (m *ExternalDataV1Quorum) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserIds(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ExternalDataV1Quorum) validateThreshold(formats strfmt.Registry) error {

	if err := validate.Required("threshold", "body", m.Threshold); err != nil {
		return err
	}

	return nil
}

func (m *ExternalDataV1Quorum) validateUserIds(formats strfmt.Registry) error {

	if err := validate.Required("userIds", "body", m.UserIds); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this external data v1 quorum based on context it is used
func (m *ExternalDataV1Quorum) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ExternalDataV1Quorum) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ExternalDataV1Quorum) UnmarshalBinary(b []byte) error {
	var res ExternalDataV1Quorum
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}