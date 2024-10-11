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

// TransactionType transaction type
//
// swagger:model TransactionType
type TransactionType string

func NewTransactionType(value TransactionType) *TransactionType {
	return &value
}

// Pointer returns a pointer to a freshly-allocated TransactionType.
func (m TransactionType) Pointer() *TransactionType {
	return &m
}

const (

	// TransactionTypeEthereum captures enum value "TRANSACTION_TYPE_ETHEREUM"
	TransactionTypeEthereum TransactionType = "TRANSACTION_TYPE_ETHEREUM"

	// TransactionTypeSolana captures enum value "TRANSACTION_TYPE_SOLANA"
	TransactionTypeSolana TransactionType = "TRANSACTION_TYPE_SOLANA"
)

// for schema
var TransactionTypeEnum []TransactionType

func init() {
	var res []TransactionType
	if err := json.Unmarshal([]byte(`["TRANSACTION_TYPE_ETHEREUM","TRANSACTION_TYPE_SOLANA"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		TransactionTypeEnum = append(TransactionTypeEnum, v)
	}
}

func (m TransactionType) validateTransactionTypeEnum(path, location string, value TransactionType) error {
	if err := validate.EnumCase(path, location, value, TransactionTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this transaction type
func (m TransactionType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateTransactionTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this transaction type based on context it is used
func (m TransactionType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
