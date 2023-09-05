// Code generated by go-swagger; DO NOT EDIT.

package policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceUpdatePolicyReader is a Reader for the PublicAPIServiceUpdatePolicy structure.
type PublicAPIServiceUpdatePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceUpdatePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceUpdatePolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceUpdatePolicyDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceUpdatePolicyOK creates a PublicAPIServiceUpdatePolicyOK with default headers values
func NewPublicAPIServiceUpdatePolicyOK() *PublicAPIServiceUpdatePolicyOK {
	return &PublicAPIServiceUpdatePolicyOK{}
}

/*
PublicAPIServiceUpdatePolicyOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceUpdatePolicyOK struct {
	Payload *models.V1ActivityResponse
}

// IsSuccess returns true when this public Api service update policy o k response has a 2xx status code
func (o *PublicAPIServiceUpdatePolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service update policy o k response has a 3xx status code
func (o *PublicAPIServiceUpdatePolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service update policy o k response has a 4xx status code
func (o *PublicAPIServiceUpdatePolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service update policy o k response has a 5xx status code
func (o *PublicAPIServiceUpdatePolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service update policy o k response a status code equal to that given
func (o *PublicAPIServiceUpdatePolicyOK) IsCode(code int) bool {
	return code == 200
}

func (o *PublicAPIServiceUpdatePolicyOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_policy][%d] publicApiServiceUpdatePolicyOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceUpdatePolicyOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_policy][%d] publicApiServiceUpdatePolicyOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceUpdatePolicyOK) GetPayload() *models.V1ActivityResponse {
	return o.Payload
}

func (o *PublicAPIServiceUpdatePolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceUpdatePolicyDefault creates a PublicAPIServiceUpdatePolicyDefault with default headers values
func NewPublicAPIServiceUpdatePolicyDefault(code int) *PublicAPIServiceUpdatePolicyDefault {
	return &PublicAPIServiceUpdatePolicyDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceUpdatePolicyDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceUpdatePolicyDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// Code gets the status code for the public Api service update policy default response
func (o *PublicAPIServiceUpdatePolicyDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this public Api service update policy default response has a 2xx status code
func (o *PublicAPIServiceUpdatePolicyDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service update policy default response has a 3xx status code
func (o *PublicAPIServiceUpdatePolicyDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service update policy default response has a 4xx status code
func (o *PublicAPIServiceUpdatePolicyDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service update policy default response has a 5xx status code
func (o *PublicAPIServiceUpdatePolicyDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service update policy default response a status code equal to that given
func (o *PublicAPIServiceUpdatePolicyDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *PublicAPIServiceUpdatePolicyDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_policy][%d] PublicApiService_UpdatePolicy default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceUpdatePolicyDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_policy][%d] PublicApiService_UpdatePolicy default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceUpdatePolicyDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceUpdatePolicyDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
