// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// Immutableactivityv1AddressFormat immutableactivityv1 address format
//
// swagger:model immutableactivityv1AddressFormat
type Immutableactivityv1AddressFormat string

func NewImmutableactivityv1AddressFormat(value Immutableactivityv1AddressFormat) *Immutableactivityv1AddressFormat {
	return &value
}

// Pointer returns a pointer to a freshly-allocated Immutableactivityv1AddressFormat.
func (m Immutableactivityv1AddressFormat) Pointer() *Immutableactivityv1AddressFormat {
	return &m
}

const (

	// Immutableactivityv1AddressFormatADDRESSFORMATUNCOMPRESSED captures enum value "ADDRESS_FORMAT_UNCOMPRESSED"
	Immutableactivityv1AddressFormatADDRESSFORMATUNCOMPRESSED Immutableactivityv1AddressFormat = "ADDRESS_FORMAT_UNCOMPRESSED"

	// Immutableactivityv1AddressFormatADDRESSFORMATCOMPRESSED captures enum value "ADDRESS_FORMAT_COMPRESSED"
	Immutableactivityv1AddressFormatADDRESSFORMATCOMPRESSED Immutableactivityv1AddressFormat = "ADDRESS_FORMAT_COMPRESSED"

	// Immutableactivityv1AddressFormatADDRESSFORMATETHEREUM captures enum value "ADDRESS_FORMAT_ETHEREUM"
	Immutableactivityv1AddressFormatADDRESSFORMATETHEREUM Immutableactivityv1AddressFormat = "ADDRESS_FORMAT_ETHEREUM"
)

// for schema
var immutableactivityv1AddressFormatEnum []interface{}

func init() {
	var res []Immutableactivityv1AddressFormat
	if err := json.Unmarshal([]byte(`["ADDRESS_FORMAT_UNCOMPRESSED","ADDRESS_FORMAT_COMPRESSED","ADDRESS_FORMAT_ETHEREUM"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		immutableactivityv1AddressFormatEnum = append(immutableactivityv1AddressFormatEnum, v)
	}
}

func (m Immutableactivityv1AddressFormat) validateImmutableactivityv1AddressFormatEnum(path, location string, value Immutableactivityv1AddressFormat) error {
	if err := validate.EnumCase(path, location, value, immutableactivityv1AddressFormatEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this immutableactivityv1 address format
func (m Immutableactivityv1AddressFormat) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateImmutableactivityv1AddressFormatEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this immutableactivityv1 address format based on context it is used
func (m Immutableactivityv1AddressFormat) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
