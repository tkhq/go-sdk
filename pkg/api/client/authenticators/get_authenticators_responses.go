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

// GetAuthenticatorsReader is a Reader for the GetAuthenticators structure.
type GetAuthenticatorsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAuthenticatorsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAuthenticatorsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/query/get_authenticators] GetAuthenticators", response, response.Code())
	}
}

// NewGetAuthenticatorsOK creates a GetAuthenticatorsOK with default headers values
func NewGetAuthenticatorsOK() *GetAuthenticatorsOK {
	return &GetAuthenticatorsOK{}
}

/*
GetAuthenticatorsOK describes a response with status code 200, with default header values.

A successful response.
*/
type GetAuthenticatorsOK struct {
	Payload *models.GetAuthenticatorsResponse
}

// IsSuccess returns true when this get authenticators o k response has a 2xx status code
func (o *GetAuthenticatorsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get authenticators o k response has a 3xx status code
func (o *GetAuthenticatorsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authenticators o k response has a 4xx status code
func (o *GetAuthenticatorsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get authenticators o k response has a 5xx status code
func (o *GetAuthenticatorsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get authenticators o k response a status code equal to that given
func (o *GetAuthenticatorsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get authenticators o k response
func (o *GetAuthenticatorsOK) Code() int {
	return 200
}

func (o *GetAuthenticatorsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/get_authenticators][%d] getAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *GetAuthenticatorsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/query/get_authenticators][%d] getAuthenticatorsOK  %+v", 200, o.Payload)
}

func (o *GetAuthenticatorsOK) GetPayload() *models.GetAuthenticatorsResponse {
	return o.Payload
}

func (o *GetAuthenticatorsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetAuthenticatorsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
