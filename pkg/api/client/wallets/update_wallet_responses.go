// Code generated by go-swagger; DO NOT EDIT.

package wallets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// UpdateWalletReader is a Reader for the UpdateWallet structure.
type UpdateWalletReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateWalletReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateWalletOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/update_wallet] UpdateWallet", response, response.Code())
	}
}

// NewUpdateWalletOK creates a UpdateWalletOK with default headers values
func NewUpdateWalletOK() *UpdateWalletOK {
	return &UpdateWalletOK{}
}

/*
UpdateWalletOK describes a response with status code 200, with default header values.

A successful response.
*/
type UpdateWalletOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this update wallet o k response has a 2xx status code
func (o *UpdateWalletOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update wallet o k response has a 3xx status code
func (o *UpdateWalletOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update wallet o k response has a 4xx status code
func (o *UpdateWalletOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update wallet o k response has a 5xx status code
func (o *UpdateWalletOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update wallet o k response a status code equal to that given
func (o *UpdateWalletOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update wallet o k response
func (o *UpdateWalletOK) Code() int {
	return 200
}

func (o *UpdateWalletOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_wallet][%d] updateWalletOK  %+v", 200, o.Payload)
}

func (o *UpdateWalletOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_wallet][%d] updateWalletOK  %+v", 200, o.Payload)
}

func (o *UpdateWalletOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *UpdateWalletOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
