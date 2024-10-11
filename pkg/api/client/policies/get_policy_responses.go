// Code generated by go-swagger; DO NOT EDIT.

package policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// GetPolicyReader is a Reader for the GetPolicy structure.
type GetPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/query/get_policy] GetPolicy", response, response.Code())
	}
}

// NewGetPolicyOK creates a GetPolicyOK with default headers values
func NewGetPolicyOK() *GetPolicyOK {
	return &GetPolicyOK{}
}

/*
GetPolicyOK describes a response with status code 200, with default header values.

A successful response.
*/
type GetPolicyOK struct {
	Payload *models.GetPolicyResponse
}

// IsSuccess returns true when this get policy o k response has a 2xx status code
func (o *GetPolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get policy o k response has a 3xx status code
func (o *GetPolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy o k response has a 4xx status code
func (o *GetPolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get policy o k response has a 5xx status code
func (o *GetPolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get policy o k response a status code equal to that given
func (o *GetPolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get policy o k response
func (o *GetPolicyOK) Code() int {
	return 200
}

func (o *GetPolicyOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/query/get_policy][%d] getPolicyOK %s", 200, payload)
}

func (o *GetPolicyOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/query/get_policy][%d] getPolicyOK %s", 200, payload)
}

func (o *GetPolicyOK) GetPayload() *models.GetPolicyResponse {
	return o.Payload
}

func (o *GetPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetPolicyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
