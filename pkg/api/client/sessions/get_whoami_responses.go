// Code generated by go-swagger; DO NOT EDIT.

package sessions

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// GetWhoamiReader is a Reader for the GetWhoami structure.
type GetWhoamiReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetWhoamiReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetWhoamiOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/query/whoami] GetWhoami", response, response.Code())
	}
}

// NewGetWhoamiOK creates a GetWhoamiOK with default headers values
func NewGetWhoamiOK() *GetWhoamiOK {
	return &GetWhoamiOK{}
}

/*
GetWhoamiOK describes a response with status code 200, with default header values.

A successful response.
*/
type GetWhoamiOK struct {
	Payload *models.GetWhoamiResponse
}

// IsSuccess returns true when this get whoami o k response has a 2xx status code
func (o *GetWhoamiOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get whoami o k response has a 3xx status code
func (o *GetWhoamiOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get whoami o k response has a 4xx status code
func (o *GetWhoamiOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get whoami o k response has a 5xx status code
func (o *GetWhoamiOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get whoami o k response a status code equal to that given
func (o *GetWhoamiOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get whoami o k response
func (o *GetWhoamiOK) Code() int {
	return 200
}

func (o *GetWhoamiOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/whoami][%d] getWhoamiOK  %+v", 200, o.Payload)
}

func (o *GetWhoamiOK) String() string {
	return fmt.Sprintf("[POST /public/v1/query/whoami][%d] getWhoamiOK  %+v", 200, o.Payload)
}

func (o *GetWhoamiOK) GetPayload() *models.GetWhoamiResponse {
	return o.Payload
}

func (o *GetWhoamiOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetWhoamiResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}