// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DeletePrivateKeyTagsRequest delete private key tags request
//
// swagger:model DeletePrivateKeyTagsRequest
type DeletePrivateKeyTagsRequest struct {

	// Unique identifier for a given Organization.
	// Required: true
	OrganizationID *string `json:"organizationId"`

	// parameters
	// Required: true
	Parameters *DeletePrivateKeyTagsIntent `json:"parameters"`

	// Timestamp (in milliseconds) of the request, used to verify liveness of user requests.
	// Required: true
	TimestampMs *string `json:"timestampMs"`

	// type
	// Required: true
	// Enum: [ACTIVITY_TYPE_DELETE_PRIVATE_KEY_TAGS]
	Type *string `json:"type"`
}

// Validate validates this delete private key tags request
func (m *DeletePrivateKeyTagsRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOrganizationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateParameters(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimestampMs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeletePrivateKeyTagsRequest) validateOrganizationID(formats strfmt.Registry) error {

	if err := validate.Required("organizationId", "body", m.OrganizationID); err != nil {
		return err
	}

	return nil
}

func (m *DeletePrivateKeyTagsRequest) validateParameters(formats strfmt.Registry) error {

	if err := validate.Required("parameters", "body", m.Parameters); err != nil {
		return err
	}

	if m.Parameters != nil {
		if err := m.Parameters.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("parameters")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("parameters")
			}
			return err
		}
	}

	return nil
}

func (m *DeletePrivateKeyTagsRequest) validateTimestampMs(formats strfmt.Registry) error {

	if err := validate.Required("timestampMs", "body", m.TimestampMs); err != nil {
		return err
	}

	return nil
}

var deletePrivateKeyTagsRequestTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ACTIVITY_TYPE_DELETE_PRIVATE_KEY_TAGS"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		deletePrivateKeyTagsRequestTypeTypePropEnum = append(deletePrivateKeyTagsRequestTypeTypePropEnum, v)
	}
}

const (

	// DeletePrivateKeyTagsRequestTypeACTIVITYTYPEDELETEPRIVATEKEYTAGS captures enum value "ACTIVITY_TYPE_DELETE_PRIVATE_KEY_TAGS"
	DeletePrivateKeyTagsRequestTypeACTIVITYTYPEDELETEPRIVATEKEYTAGS string = "ACTIVITY_TYPE_DELETE_PRIVATE_KEY_TAGS"
)

// prop value enum
func (m *DeletePrivateKeyTagsRequest) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, deletePrivateKeyTagsRequestTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *DeletePrivateKeyTagsRequest) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", *m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this delete private key tags request based on the context it is used
func (m *DeletePrivateKeyTagsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateParameters(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeletePrivateKeyTagsRequest) contextValidateParameters(ctx context.Context, formats strfmt.Registry) error {

	if m.Parameters != nil {

		if err := m.Parameters.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("parameters")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("parameters")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DeletePrivateKeyTagsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeletePrivateKeyTagsRequest) UnmarshalBinary(b []byte) error {
	var res DeletePrivateKeyTagsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
