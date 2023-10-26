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

// CreateAuthenticatorsReader is a Reader for the CreateAuthenticators structure.
type CreateAuthenticatorsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAuthenticatorsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateAuthenticatorsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAuthenticatorsOK creates a CreateAuthenticatorsOK with default headers values
func NewCreateAuthenticatorsOK() *CreateAuthenticatorsOK {
	return &CreateAuthenticatorsOK{}
}

/*
CreateAuthenticatorsOK describes a response with status code 200, with default header values.

A successful response.
*/
type CreateAuthenticatorsOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this create authenticators o k response has a 2xx status code
func (o *CreateAuthenticatorsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create authenticators o k response has a 3xx status code
func (o *CreateAuthenticatorsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authenticators o k response has a 4xx status code
func (o *CreateAuthenticatorsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create authenticators o k response has a 5xx status code
func (o *CreateAuthenticatorsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create authenticators o k response a status code equal to that given
func (o *CreateAuthenticatorsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create authenticators o k response
func (o *CreateAuthenticatorsOK) Code() int {
	return 200
}

func (o *CreateAuthenticatorsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_authenticators][%d] createAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *CreateAuthenticatorsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_authenticators][%d] createAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *CreateAuthenticatorsOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *CreateAuthenticatorsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
