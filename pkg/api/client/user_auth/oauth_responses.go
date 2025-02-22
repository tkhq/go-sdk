// Code generated by go-swagger; DO NOT EDIT.

package user_auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// OauthReader is a Reader for the Oauth structure.
type OauthReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OauthReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOauthOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/oauth] Oauth", response, response.Code())
	}
}

// NewOauthOK creates a OauthOK with default headers values
func NewOauthOK() *OauthOK {
	return &OauthOK{}
}

/*
OauthOK describes a response with status code 200, with default header values.

A successful response.
*/
type OauthOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this oauth o k response has a 2xx status code
func (o *OauthOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this oauth o k response has a 3xx status code
func (o *OauthOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this oauth o k response has a 4xx status code
func (o *OauthOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this oauth o k response has a 5xx status code
func (o *OauthOK) IsServerError() bool {
	return false
}

// IsCode returns true when this oauth o k response a status code equal to that given
func (o *OauthOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the oauth o k response
func (o *OauthOK) Code() int {
	return 200
}

func (o *OauthOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/oauth][%d] oauthOK  %+v", 200, o.Payload)
}

func (o *OauthOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/oauth][%d] oauthOK  %+v", 200, o.Payload)
}

func (o *OauthOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *OauthOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
