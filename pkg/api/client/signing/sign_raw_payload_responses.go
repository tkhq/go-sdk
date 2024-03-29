// Code generated by go-swagger; DO NOT EDIT.

package signing

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// SignRawPayloadReader is a Reader for the SignRawPayload structure.
type SignRawPayloadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SignRawPayloadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSignRawPayloadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/sign_raw_payload] SignRawPayload", response, response.Code())
	}
}

// NewSignRawPayloadOK creates a SignRawPayloadOK with default headers values
func NewSignRawPayloadOK() *SignRawPayloadOK {
	return &SignRawPayloadOK{}
}

/*
SignRawPayloadOK describes a response with status code 200, with default header values.

A successful response.
*/
type SignRawPayloadOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this sign raw payload o k response has a 2xx status code
func (o *SignRawPayloadOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sign raw payload o k response has a 3xx status code
func (o *SignRawPayloadOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sign raw payload o k response has a 4xx status code
func (o *SignRawPayloadOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sign raw payload o k response has a 5xx status code
func (o *SignRawPayloadOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sign raw payload o k response a status code equal to that given
func (o *SignRawPayloadOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sign raw payload o k response
func (o *SignRawPayloadOK) Code() int {
	return 200
}

func (o *SignRawPayloadOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] signRawPayloadOK  %+v", 200, o.Payload)
}

func (o *SignRawPayloadOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] signRawPayloadOK  %+v", 200, o.Payload)
}

func (o *SignRawPayloadOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *SignRawPayloadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
