// Code generated by go-swagger; DO NOT EDIT.

package wallets

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

// InitImportWalletReader is a Reader for the InitImportWallet structure.
type InitImportWalletReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InitImportWalletReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInitImportWalletOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/init_import_wallet] InitImportWallet", response, response.Code())
	}
}

// NewInitImportWalletOK creates a InitImportWalletOK with default headers values
func NewInitImportWalletOK() *InitImportWalletOK {
	return &InitImportWalletOK{}
}

/*
InitImportWalletOK describes a response with status code 200, with default header values.

A successful response.
*/
type InitImportWalletOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this init import wallet o k response has a 2xx status code
func (o *InitImportWalletOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this init import wallet o k response has a 3xx status code
func (o *InitImportWalletOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this init import wallet o k response has a 4xx status code
func (o *InitImportWalletOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this init import wallet o k response has a 5xx status code
func (o *InitImportWalletOK) IsServerError() bool {
	return false
}

// IsCode returns true when this init import wallet o k response a status code equal to that given
func (o *InitImportWalletOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the init import wallet o k response
func (o *InitImportWalletOK) Code() int {
	return 200
}

func (o *InitImportWalletOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/init_import_wallet][%d] initImportWalletOK %s", 200, payload)
}

func (o *InitImportWalletOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/init_import_wallet][%d] initImportWalletOK %s", 200, payload)
}

func (o *InitImportWalletOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *InitImportWalletOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
