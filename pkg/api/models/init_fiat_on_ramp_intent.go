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

// InitFiatOnRampIntent init fiat on ramp intent
//
// swagger:model InitFiatOnRampIntent
type InitFiatOnRampIntent struct {

	// ISO 3166-1 two-digit country code for Coinbase representing the purchasing user’s country of residence, e.g., US, GB.
	CountryCode *string `json:"countryCode,omitempty"`

	// ISO 3166-2 two-digit country subdivision code for Coinbase representing the purchasing user’s subdivision of residence within their country, e.g. NY. Required if country_code=US.
	CountrySubdivisionCode *string `json:"countrySubdivisionCode,omitempty"`

	// Code for the cryptocurrency to be purchased, e.g., btc, eth. Maps to MoonPay's currencyCode or Coinbase's defaultAsset.
	// Required: true
	CryptoCurrencyCode *FiatOnRampCryptoCurrency `json:"cryptoCurrencyCode"`

	// Specifies a preset fiat amount for the transaction, e.g., '100'. Must be greater than '20'. If not provided, the user will be prompted to enter an amount.
	FiatCurrencyAmount *string `json:"fiatCurrencyAmount,omitempty"`

	// Code for the fiat currency to be used in the transaction, e.g., USD, EUR.
	FiatCurrencyCode FiatOnRampCurrency `json:"fiatCurrencyCode,omitempty"`

	// Blockchain network to be used for the transaction, e.g., bitcoin, ethereum. Maps to MoonPay's network or Coinbase's defaultNetwork.
	// Required: true
	Network *FiatOnRampBlockchainNetwork `json:"network"`

	// Enum to specifiy which on-ramp provider to use
	// Required: true
	OnrampProvider *FiatOnRampProvider `json:"onrampProvider"`

	// Pre-selected payment method, e.g., CREDIT_DEBIT_CARD, APPLE_PAY. Validated against the chosen provider.
	PaymentMethod FiatOnRampPaymentMethod `json:"paymentMethod,omitempty"`

	// Destination wallet address for the buy transaction.
	// Required: true
	WalletAddress *string `json:"walletAddress"`
}

// Validate validates this init fiat on ramp intent
func (m *InitFiatOnRampIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCryptoCurrencyCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFiatCurrencyCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNetwork(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOnrampProvider(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWalletAddress(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InitFiatOnRampIntent) validateCryptoCurrencyCode(formats strfmt.Registry) error {

	if err := validate.Required("cryptoCurrencyCode", "body", m.CryptoCurrencyCode); err != nil {
		return err
	}

	if err := validate.Required("cryptoCurrencyCode", "body", m.CryptoCurrencyCode); err != nil {
		return err
	}

	if m.CryptoCurrencyCode != nil {
		if err := m.CryptoCurrencyCode.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cryptoCurrencyCode")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cryptoCurrencyCode")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) validateFiatCurrencyCode(formats strfmt.Registry) error {
	if swag.IsZero(m.FiatCurrencyCode) { // not required
		return nil
	}

	if err := m.FiatCurrencyCode.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("fiatCurrencyCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("fiatCurrencyCode")
		}
		return err
	}

	return nil
}

func (m *InitFiatOnRampIntent) validateNetwork(formats strfmt.Registry) error {

	if err := validate.Required("network", "body", m.Network); err != nil {
		return err
	}

	if err := validate.Required("network", "body", m.Network); err != nil {
		return err
	}

	if m.Network != nil {
		if err := m.Network.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("network")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("network")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) validateOnrampProvider(formats strfmt.Registry) error {

	if err := validate.Required("onrampProvider", "body", m.OnrampProvider); err != nil {
		return err
	}

	if err := validate.Required("onrampProvider", "body", m.OnrampProvider); err != nil {
		return err
	}

	if m.OnrampProvider != nil {
		if err := m.OnrampProvider.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("onrampProvider")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("onrampProvider")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) validatePaymentMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentMethod) { // not required
		return nil
	}

	if err := m.PaymentMethod.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("paymentMethod")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("paymentMethod")
		}
		return err
	}

	return nil
}

func (m *InitFiatOnRampIntent) validateWalletAddress(formats strfmt.Registry) error {

	if err := validate.Required("walletAddress", "body", m.WalletAddress); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this init fiat on ramp intent based on the context it is used
func (m *InitFiatOnRampIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCryptoCurrencyCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFiatCurrencyCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNetwork(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOnrampProvider(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePaymentMethod(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InitFiatOnRampIntent) contextValidateCryptoCurrencyCode(ctx context.Context, formats strfmt.Registry) error {

	if m.CryptoCurrencyCode != nil {

		if err := m.CryptoCurrencyCode.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cryptoCurrencyCode")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cryptoCurrencyCode")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) contextValidateFiatCurrencyCode(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.FiatCurrencyCode) { // not required
		return nil
	}

	if err := m.FiatCurrencyCode.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("fiatCurrencyCode")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("fiatCurrencyCode")
		}
		return err
	}

	return nil
}

func (m *InitFiatOnRampIntent) contextValidateNetwork(ctx context.Context, formats strfmt.Registry) error {

	if m.Network != nil {

		if err := m.Network.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("network")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("network")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) contextValidateOnrampProvider(ctx context.Context, formats strfmt.Registry) error {

	if m.OnrampProvider != nil {

		if err := m.OnrampProvider.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("onrampProvider")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("onrampProvider")
			}
			return err
		}
	}

	return nil
}

func (m *InitFiatOnRampIntent) contextValidatePaymentMethod(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.PaymentMethod) { // not required
		return nil
	}

	if err := m.PaymentMethod.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("paymentMethod")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("paymentMethod")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *InitFiatOnRampIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InitFiatOnRampIntent) UnmarshalBinary(b []byte) error {
	var res InitFiatOnRampIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
