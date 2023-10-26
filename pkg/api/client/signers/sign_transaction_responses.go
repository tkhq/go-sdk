// Code generated by go-swagger; DO NOT EDIT.

package signers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// SignTransactionReader is a Reader for the SignTransaction structure.
type SignTransactionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SignTransactionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSignTransactionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSignTransactionOK creates a SignTransactionOK with default headers values
func NewSignTransactionOK() *SignTransactionOK {
	return &SignTransactionOK{}
}

/*
SignTransactionOK describes a response with status code 200, with default header values.

A successful response.
*/
type SignTransactionOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this sign transaction o k response has a 2xx status code
func (o *SignTransactionOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sign transaction o k response has a 3xx status code
func (o *SignTransactionOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sign transaction o k response has a 4xx status code
func (o *SignTransactionOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sign transaction o k response has a 5xx status code
func (o *SignTransactionOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sign transaction o k response a status code equal to that given
func (o *SignTransactionOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sign transaction o k response
func (o *SignTransactionOK) Code() int {
	return 200
}

func (o *SignTransactionOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_transaction][%d] signTransactionOK  %+v", 200, o.Payload)
}

func (o *SignTransactionOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_transaction][%d] signTransactionOK  %+v", 200, o.Payload)
}

func (o *SignTransactionOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *SignTransactionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
