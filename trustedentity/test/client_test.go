/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package trustedentityTest

import (
	"log"
	"testing"
	"google.golang.org/grpc"
	pb "github.com/peernova-private/sandbox-mr/trustedentity/protobuf"
	"golang.org/x/net/context"
	"github.com/peernova-private/cuneiform/src/gore/pntest"
	api "github.com/hashicorp/vault/api"
	"strings"
)


const (
	address     = "localhost:50051"
	defaultName = "world"
	vaultAddr = "http://192.168.0.50:8200"
	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
)


type PKIDataType struct {
	certificate interface {}
	issuingCA interface {}
	privateKey interface {}
	privateKeyType interface {}
	serialNumber interface {}
}

/*
	The function reads data items from a given path. It is used in a generic test.

	verb - 			specifies action on the Vault as per Vault API, e.g. "List" or "Read"
	path - 			the Vault path, e.g. "pki/cert/ca"
	itemTitle -		title of the retrieved item
	dataItemName - 	name of the retrieved item
	vaultPar -		pointer to the Vault interface
*/
func readPKIByVerb (
	verb string,
	path string,
	itemTitle string,
	dataItemName string,
	vaultPar *api.Logical) {
	var err error
	var s *api.Secret

	log.Printf("\n\nReading Vault '%s': '%s'", itemTitle, path)
	if verb == "List" {
		s, err = vaultPar.List(path)
	} else if verb == "Read" {
		s, err = vaultPar.Read(path)
	}

	if err != nil {
		log.Fatalf("Reading Vault '%s' from '%s' failed: %v", itemTitle, path, err)
	} else {
		if s == nil {
			log.Fatalf("Vault '%s' was nil", itemTitle)
		} else {
			dataItemValue := s.Data[dataItemName]
			log.Printf("The '%s' ['%s']: \n%s", itemTitle, dataItemName, dataItemValue, dataItemValue)
		}
	}
	return
}

/*
	The function reads a certificate element for a given serial number.

	path - 			the Vault path, e.g. "pki/cert"
	serialNumber -	serial number of the retrieved certificate
	vaultPar -		pointer to the Vault interface

	Returns - a certificate in string format
*/
func readPKICertificateBySerialNumber (
	path 			string,
	serialNumber 	string,
	vaultPar 		*api.Logical) string {
	var err error
	var s *api.Secret
	var retValue string

	fullPath := path + serialNumber
	log.Printf("\n\nreadPKICertificateBySerialNumber: Reading Vault: '%s'", fullPath)
	s, err = vaultPar.Read(fullPath)

	if err != nil {
		log.Fatalf("readPKICertificateBySerialNumber: Reading Vault from '%s' failed: %v", fullPath, err)
	} else {
		if s == nil {
			log.Fatalf("readPKICertificateBySerialNumber: Vault was nil")
		} else {
			dataItemValue, err1 := s.Data["certificate"].(string)
			if !err1 {
				log.Fatalf("readPKICertificateBySerialNumber: PKI Property %s is not a string %v", "certificate", err1)
			}
			log.Printf("readPKICertificateBySerialNumber: the '%s': \n%s", "certificate", dataItemValue)
			retValue = dataItemValue
		}
	}
	return retValue
}

/*
	The function creates and returns a new certificate.

	role - 			the role for which the certificate is created
	commonName -	the common name
	ttl - 			time to live for the certificate
	vaultPar -		pointer to the Vault interface

	Returns - the following type PKIDataType struct:
					{
					certificate interface {}
					issuingCA interface {}
					privateKey interface {}
					privateKeyType interface {}
					serialNumber interface {}
					}
*/
func createPKICertificate (
	role string,
	commonName string,
	ttl string,
	vaultPar *api.Logical) PKIDataType {
	var s1 *api.Secret
	var err error
	var retValue PKIDataType
	var certificate interface {}
	var issuingCA interface {}
	var privateKey interface {}
	var privateKeyType interface {}
	var serialNumber interface {}

	log.Printf("\n\nCreating certificate in the Vault in createPKICertificate:")
	s1, err = vaultPar.Write("pki/issue/" + role,
		map[string]interface{}{
			"common_name": commonName,
			"ttl":         ttl,
		})
	if err == nil {
		certificate = strings.TrimSpace(s1.Data["certificate"].(string))
		issuingCA = strings.TrimSpace(s1.Data["issuing_ca"].(string))
		privateKey = strings.TrimSpace(s1.Data["private_key"].(string))
		privateKeyType = s1.Data["private_key_type"].(string)
		serialNumber = s1.Data["serial_number"]
		//log.Printf("createPKICertificate.certificate: %s", certificate)
		//log.Printf("createPKICertificate.issuing_ca: %s", issuingCA)
		//log.Printf("createPKICertificate.private_key: %s ( key type: %s)", privateKey, privateKeyType)
		//log.Printf("createPKICertificate.serial_number: %v", serialNumber)

		// Return the struct
		retValue.certificate = certificate
		retValue.issuingCA = issuingCA
		retValue.privateKey = privateKey
		retValue.privateKeyType = privateKeyType
		retValue.serialNumber = serialNumber
	} else {
		log.Printf("Error in createPKICertificate: %v", err)
	}
	return retValue
}
//
// Tests validating various workflows
//
// TestTrustedEntityClient_TestReadSecret() - reads the secret/production/qa
// TestTrustedEntityClient_TestReadCACertificate() - reads the CA certificate
// TestTrustedEntityClient_TestCurrentCRL() - reads the current CRL
// TestTrustedEntityClient_TestCreateCACertificate() - creates a CA certificate and reads it for verification.
//

func TestTrustedEntityClient_TestReadSecret(t *testing.T) {
	log.Print("\n********** Begin testing gRPC: Read secret endpoint v1.0 - test_workflow1 Step1 **********\n")
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	defer conn.Close()
	pntest.NoError(t, err)
	c := pb.NewSecretKeeperClient(conn)

	// Read a secret from the Vault
	var secretRequest pb.SecretRequest
	secretRequest.SecretPath = "secret/production/qa"
	r, err := c.SaySecret(context.Background(), &secretRequest)
	if err != nil {
		log.Printf("could not request a secret %s: %v", secretRequest.SecretPath, err)
	}
	log.Printf("\n\nSaySecret() returned: %s", r.Message)
	log.Print("\n********** End testing gRPC: Read secret endpoint v1.0 - test_workflow1 Step1 **********\n")
}

func TestTrustedEntityClient_TestReadCACertificate(t *testing.T) {
	log.Print("\n********** Begin testing ReadCACertificate endpoint v1.0 - test_workflow1 Step2 **********\n")
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	defer conn.Close()
	pntest.NoError(t, err)
	c := pb.NewSecretKeeperClient(conn)


	// Read the CA certificate from the Vault
	r1, err := c.SayCACertificate(context.Background(), &pb.CACertificateRequest{})
	if err != nil {
		log.Printf("could not request a CA certificate: %v", err)
	}
	log.Printf("\n\nRequested a CA certificate: \n%s", r1.Message)
	log.Print("\n********** End testing ReadCACertificate endpoint v1.0 **********\n")
}

func TestTrustedEntityClient_TestCurrentCRL(t *testing.T) {
	log.Print("\n********** Begin testing Read Current CRL v1.0  - test_workflow1 Step3 **********\n")
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	defer conn.Close()
	pntest.NoError(t, err)
	c := pb.NewSecretKeeperClient(conn)

	// Read the current CRL from the Vault
	r2, err := c.SayCurrentCRL(context.Background(), &pb.CurrentCRLRequest{})
	if err != nil {
		log.Printf("could not request a current CRL: %v", err)
	}
	log.Printf("\n\nRequested current CRL: \n%s", r2.Message)
	log.Print("\n********** End testing Read Current CRL endpoint v1.0 **********\n")
}

func TestTrustedEntityClient_TestCreateCACertificate(t *testing.T) {
	log.Print("\n********** Begin testing Create PKI Certificate v1.0  - test_workflow1 Step4 **********\n")
	var newCertificateWithSN PKIDataType
	log.Print("\n\n********** Testing createPKICertificate - test_workflow1 **********\n")
	vaultCFG := api.DefaultConfig()
	vaultCFG.Address = vaultAddr

	var err error
	vClient, err := api.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(vaultToken)
	vault := vClient.Logical()	// Create a new certificate and read it by serial number for verification
	newCertificateWithSN = createPKICertificate (
		"peernova-dot-com",
		"blah2.peernova.com",
		"100h",
		vault)

	log.Printf("\nworkflow1(): New certificate written to the Vault:\n")
	log.Print(newCertificateWithSN.certificate)
	log.Printf("\nworkflow1(): New issuing CA written to the Vault:\n")
	log.Print(newCertificateWithSN.issuingCA)
	log.Printf("\nworkflow1(): New private Key written to the Vault:\n")
	log.Print(newCertificateWithSN.privateKey)
	log.Printf("\nworkflow1(): New serial Number written to the Vault:\n")
	log.Print(newCertificateWithSN.serialNumber)

	if newCertificateWithSN.serialNumber != nil {
		var retrievedCertificate string
		serialNumber := newCertificateWithSN.serialNumber

		// Read CA certificate again
		log.Print("\n\nworkflow1(): Read the certificate by its SN from the Vault again:")
		retrievedCertificate = readPKICertificateBySerialNumber (
			"pki/cert/",
			serialNumber.(string),
			vault)

		var newCertificate = (newCertificateWithSN.certificate).(string)
		var trimmedNewCertificateString = strings.TrimSpace(newCertificate)
		var trimmedRetrievedCertificate = strings.TrimSpace(retrievedCertificate)

		log.Printf("\nworkflow1(): Certificate retrieved from the Vault by readPKICertificateBySerialNumber:\n")
		log.Print("retrievedCertificate:",len(retrievedCertificate), "-", retrievedCertificate)
		log.Printf("\nworkflow1(): Certificate written to the Vault by writePKICertificate:\n")
		log.Print("writtenCertificate:",len(newCertificate), "-", newCertificate)
		log.Print(trimmedNewCertificateString)

		if strings.Compare(trimmedRetrievedCertificate, trimmedNewCertificateString) == 0 {
			log.Print("\nworkflow1(): The certificate written to the Vault was retrieved successfully.")
		} else {
			log.Print("Certificates did not match")
		}
	} else {
		log.Printf("\nworkflow1(): Writing to the Vault failed: %s", err.Error())
	}
	log.Print("\n********** End testing createPKICertificate **********\n")
	log.Print("\n********** End testing Create PKI Certificate v1.0  - test_workflow1 Step4 **********\n")
}
