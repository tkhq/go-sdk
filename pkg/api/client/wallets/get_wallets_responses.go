// Code generated by go-swagger; DO NOT EDIT.

package wallets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// GetWalletsReader is a Reader for the GetWallets structure.
type GetWalletsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetWalletsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetWalletsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetWalletsOK creates a GetWalletsOK with default headers values
func NewGetWalletsOK() *GetWalletsOK {
	return &GetWalletsOK{}
}

/*
GetWalletsOK describes a response with status code 200, with default header values.

A successful response.
*/
type GetWalletsOK struct {
	Payload *models.GetWalletsResponse
}

// IsSuccess returns true when this get wallets o k response has a 2xx status code
func (o *GetWalletsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get wallets o k response has a 3xx status code
func (o *GetWalletsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get wallets o k response has a 4xx status code
func (o *GetWalletsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get wallets o k response has a 5xx status code
func (o *GetWalletsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get wallets o k response a status code equal to that given
func (o *GetWalletsOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetWalletsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/list_wallets][%d] getWalletsOK  %+v", 200, o.Payload)
}

func (o *GetWalletsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/query/list_wallets][%d] getWalletsOK  %+v", 200, o.Payload)
}

func (o *GetWalletsOK) GetPayload() *models.GetWalletsResponse {
	return o.Payload
}

func (o *GetWalletsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetWalletsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
