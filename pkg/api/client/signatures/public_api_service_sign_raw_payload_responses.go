// Code generated by go-swagger; DO NOT EDIT.

package signatures

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceSignRawPayloadReader is a Reader for the PublicAPIServiceSignRawPayload structure.
type PublicAPIServiceSignRawPayloadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceSignRawPayloadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceSignRawPayloadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceSignRawPayloadDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceSignRawPayloadOK creates a PublicAPIServiceSignRawPayloadOK with default headers values
func NewPublicAPIServiceSignRawPayloadOK() *PublicAPIServiceSignRawPayloadOK {
	return &PublicAPIServiceSignRawPayloadOK{}
}

/*
PublicAPIServiceSignRawPayloadOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceSignRawPayloadOK struct {
	Payload *models.V1ActivityResponse
}

// IsSuccess returns true when this public Api service sign raw payload o k response has a 2xx status code
func (o *PublicAPIServiceSignRawPayloadOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service sign raw payload o k response has a 3xx status code
func (o *PublicAPIServiceSignRawPayloadOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service sign raw payload o k response has a 4xx status code
func (o *PublicAPIServiceSignRawPayloadOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service sign raw payload o k response has a 5xx status code
func (o *PublicAPIServiceSignRawPayloadOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service sign raw payload o k response a status code equal to that given
func (o *PublicAPIServiceSignRawPayloadOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the public Api service sign raw payload o k response
func (o *PublicAPIServiceSignRawPayloadOK) Code() int {
	return 200
}

func (o *PublicAPIServiceSignRawPayloadOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] publicApiServiceSignRawPayloadOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceSignRawPayloadOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] publicApiServiceSignRawPayloadOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceSignRawPayloadOK) GetPayload() *models.V1ActivityResponse {
	return o.Payload
}

func (o *PublicAPIServiceSignRawPayloadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceSignRawPayloadDefault creates a PublicAPIServiceSignRawPayloadDefault with default headers values
func NewPublicAPIServiceSignRawPayloadDefault(code int) *PublicAPIServiceSignRawPayloadDefault {
	return &PublicAPIServiceSignRawPayloadDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceSignRawPayloadDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceSignRawPayloadDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this public Api service sign raw payload default response has a 2xx status code
func (o *PublicAPIServiceSignRawPayloadDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service sign raw payload default response has a 3xx status code
func (o *PublicAPIServiceSignRawPayloadDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service sign raw payload default response has a 4xx status code
func (o *PublicAPIServiceSignRawPayloadDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service sign raw payload default response has a 5xx status code
func (o *PublicAPIServiceSignRawPayloadDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service sign raw payload default response a status code equal to that given
func (o *PublicAPIServiceSignRawPayloadDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the public Api service sign raw payload default response
func (o *PublicAPIServiceSignRawPayloadDefault) Code() int {
	return o._statusCode
}

func (o *PublicAPIServiceSignRawPayloadDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] PublicApiService_SignRawPayload default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceSignRawPayloadDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/sign_raw_payload][%d] PublicApiService_SignRawPayload default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceSignRawPayloadDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceSignRawPayloadDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}