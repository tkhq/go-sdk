// Code generated by go-swagger; DO NOT EDIT.

package authenticators

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// DeleteAuthenticatorsReader is a Reader for the DeleteAuthenticators structure.
type DeleteAuthenticatorsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAuthenticatorsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteAuthenticatorsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteAuthenticatorsOK creates a DeleteAuthenticatorsOK with default headers values
func NewDeleteAuthenticatorsOK() *DeleteAuthenticatorsOK {
	return &DeleteAuthenticatorsOK{}
}

/*
DeleteAuthenticatorsOK describes a response with status code 200, with default header values.

A successful response.
*/
type DeleteAuthenticatorsOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this delete authenticators o k response has a 2xx status code
func (o *DeleteAuthenticatorsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete authenticators o k response has a 3xx status code
func (o *DeleteAuthenticatorsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete authenticators o k response has a 4xx status code
func (o *DeleteAuthenticatorsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete authenticators o k response has a 5xx status code
func (o *DeleteAuthenticatorsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete authenticators o k response a status code equal to that given
func (o *DeleteAuthenticatorsOK) IsCode(code int) bool {
	return code == 200
}

func (o *DeleteAuthenticatorsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_authenticators][%d] deleteAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *DeleteAuthenticatorsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_authenticators][%d] deleteAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *DeleteAuthenticatorsOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *DeleteAuthenticatorsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
