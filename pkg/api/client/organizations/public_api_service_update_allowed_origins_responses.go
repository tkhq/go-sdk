// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceUpdateAllowedOriginsReader is a Reader for the PublicAPIServiceUpdateAllowedOrigins structure.
type PublicAPIServiceUpdateAllowedOriginsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceUpdateAllowedOriginsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceUpdateAllowedOriginsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceUpdateAllowedOriginsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceUpdateAllowedOriginsOK creates a PublicAPIServiceUpdateAllowedOriginsOK with default headers values
func NewPublicAPIServiceUpdateAllowedOriginsOK() *PublicAPIServiceUpdateAllowedOriginsOK {
	return &PublicAPIServiceUpdateAllowedOriginsOK{}
}

/*
PublicAPIServiceUpdateAllowedOriginsOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceUpdateAllowedOriginsOK struct {
	Payload *models.V1ActivityResponse
}

// IsSuccess returns true when this public Api service update allowed origins o k response has a 2xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service update allowed origins o k response has a 3xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service update allowed origins o k response has a 4xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service update allowed origins o k response has a 5xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service update allowed origins o k response a status code equal to that given
func (o *PublicAPIServiceUpdateAllowedOriginsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the public Api service update allowed origins o k response
func (o *PublicAPIServiceUpdateAllowedOriginsOK) Code() int {
	return 200
}

func (o *PublicAPIServiceUpdateAllowedOriginsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_allowed_origins][%d] publicApiServiceUpdateAllowedOriginsOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceUpdateAllowedOriginsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_allowed_origins][%d] publicApiServiceUpdateAllowedOriginsOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceUpdateAllowedOriginsOK) GetPayload() *models.V1ActivityResponse {
	return o.Payload
}

func (o *PublicAPIServiceUpdateAllowedOriginsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceUpdateAllowedOriginsDefault creates a PublicAPIServiceUpdateAllowedOriginsDefault with default headers values
func NewPublicAPIServiceUpdateAllowedOriginsDefault(code int) *PublicAPIServiceUpdateAllowedOriginsDefault {
	return &PublicAPIServiceUpdateAllowedOriginsDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceUpdateAllowedOriginsDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceUpdateAllowedOriginsDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this public Api service update allowed origins default response has a 2xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service update allowed origins default response has a 3xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service update allowed origins default response has a 4xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service update allowed origins default response has a 5xx status code
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service update allowed origins default response a status code equal to that given
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the public Api service update allowed origins default response
func (o *PublicAPIServiceUpdateAllowedOriginsDefault) Code() int {
	return o._statusCode
}

func (o *PublicAPIServiceUpdateAllowedOriginsDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_allowed_origins][%d] PublicApiService_UpdateAllowedOrigins default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceUpdateAllowedOriginsDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_allowed_origins][%d] PublicApiService_UpdateAllowedOrigins default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceUpdateAllowedOriginsDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceUpdateAllowedOriginsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}