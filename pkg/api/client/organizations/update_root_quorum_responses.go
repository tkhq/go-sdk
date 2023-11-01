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

// UpdateRootQuorumReader is a Reader for the UpdateRootQuorum structure.
type UpdateRootQuorumReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateRootQuorumReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateRootQuorumOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/update_root_quorum] UpdateRootQuorum", response, response.Code())
	}
}

// NewUpdateRootQuorumOK creates a UpdateRootQuorumOK with default headers values
func NewUpdateRootQuorumOK() *UpdateRootQuorumOK {
	return &UpdateRootQuorumOK{}
}

/*
UpdateRootQuorumOK describes a response with status code 200, with default header values.

A successful response.
*/
type UpdateRootQuorumOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this update root quorum o k response has a 2xx status code
func (o *UpdateRootQuorumOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update root quorum o k response has a 3xx status code
func (o *UpdateRootQuorumOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update root quorum o k response has a 4xx status code
func (o *UpdateRootQuorumOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update root quorum o k response has a 5xx status code
func (o *UpdateRootQuorumOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update root quorum o k response a status code equal to that given
func (o *UpdateRootQuorumOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update root quorum o k response
func (o *UpdateRootQuorumOK) Code() int {
	return 200
}

func (o *UpdateRootQuorumOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_root_quorum][%d] updateRootQuorumOK  %+v", 200, o.Payload)
}

func (o *UpdateRootQuorumOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_root_quorum][%d] updateRootQuorumOK  %+v", 200, o.Payload)
}

func (o *UpdateRootQuorumOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *UpdateRootQuorumOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}