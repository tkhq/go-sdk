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

// Vote vote
//
// swagger:model Vote
type Vote struct {

	// Unique identifier for a given Activity object.
	// Required: true
	ActivityID *string `json:"activityId"`

	// created at
	// Required: true
	CreatedAt *ExternalDataV1Timestamp `json:"createdAt"`

	// Unique identifier for a given Vote object.
	// Required: true
	ID *string `json:"id"`

	// The raw message being signed within a Vote.
	// Required: true
	Message *string `json:"message"`

	// The public component of a cryptographic key pair used to sign messages and transactions.
	// Required: true
	PublicKey *string `json:"publicKey"`

	// Method used to produce a signature.
	// Required: true
	Scheme *string `json:"scheme"`

	// selection
	// Required: true
	// Enum: [VOTE_SELECTION_APPROVED VOTE_SELECTION_REJECTED]
	Selection *string `json:"selection"`

	// The signature applied to a particular vote.
	// Required: true
	Signature *string `json:"signature"`

	// Web and/or API user within your Organization.
	// Required: true
	User *User `json:"user"`

	// Unique identifier for a given User.
	// Required: true
	UserID *string `json:"userId"`
}

// Validate validates this vote
func (m *Vote) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActivityID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMessage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateScheme(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSelection(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSignature(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUser(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Vote) validateActivityID(formats strfmt.Registry) error {

	if err := validate.Required("activityId", "body", m.ActivityID); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validateCreatedAt(formats strfmt.Registry) error {

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

func (m *Vote) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validateMessage(formats strfmt.Registry) error {

	if err := validate.Required("message", "body", m.Message); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validateScheme(formats strfmt.Registry) error {

	if err := validate.Required("scheme", "body", m.Scheme); err != nil {
		return err
	}

	return nil
}

var voteTypeSelectionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["VOTE_SELECTION_APPROVED","VOTE_SELECTION_REJECTED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		voteTypeSelectionPropEnum = append(voteTypeSelectionPropEnum, v)
	}
}

const (

	// VoteSelectionVOTESELECTIONAPPROVED captures enum value "VOTE_SELECTION_APPROVED"
	VoteSelectionVOTESELECTIONAPPROVED string = "VOTE_SELECTION_APPROVED"

	// VoteSelectionVOTESELECTIONREJECTED captures enum value "VOTE_SELECTION_REJECTED"
	VoteSelectionVOTESELECTIONREJECTED string = "VOTE_SELECTION_REJECTED"
)

// prop value enum
func (m *Vote) validateSelectionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, voteTypeSelectionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Vote) validateSelection(formats strfmt.Registry) error {

	if err := validate.Required("selection", "body", m.Selection); err != nil {
		return err
	}

	// value enum
	if err := m.validateSelectionEnum("selection", "body", *m.Selection); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validateSignature(formats strfmt.Registry) error {

	if err := validate.Required("signature", "body", m.Signature); err != nil {
		return err
	}

	return nil
}

func (m *Vote) validateUser(formats strfmt.Registry) error {

	if err := validate.Required("user", "body", m.User); err != nil {
		return err
	}

	if m.User != nil {
		if err := m.User.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("user")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("user")
			}
			return err
		}
	}

	return nil
}

func (m *Vote) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this vote based on the context it is used
func (m *Vote) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreatedAt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUser(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Vote) contextValidateCreatedAt(ctx context.Context, formats strfmt.Registry) error {

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

func (m *Vote) contextValidateUser(ctx context.Context, formats strfmt.Registry) error {

	if m.User != nil {

		if err := m.User.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("user")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("user")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Vote) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Vote) UnmarshalBinary(b []byte) error {
	var res Vote
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
