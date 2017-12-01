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

package main

import (
	"log"
	"os"

	"net/http"
	"io/ioutil"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/peernova-private/sandbox-mr/trustedentity/protobuf"
	api "github.com/hashicorp/vault/api"
	"encoding/json"
	"strings"
	//backoff "github.com/backoff-master"
)

const (
	address     = "localhost:50051"
	defaultName = "world"
	vaultAddr = "http://192.168.0.50:8200"
	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
)


type PKIDataType struct {
	certificate string
	issuingCA string
	privateKey string
	privateKeyType string
	serialNumber string
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
			dataItemValue, ok := s.Data["certificate"].(string)
			if !ok {
				log.Fatalf("readPKICertificateBySerialNumber: PKI Property %s is not a string", "certificate")
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
	vaultPar *api.Logical) (PKIDataType, error) {
	var s1 *api.Secret
	var err error

	log.Printf("\n\nWriting certificate to the Vault in createPKICertificate for the role: '" + role + "'")
	s1, err = vaultPar.Write("pki/issue/" + role,
		map[string]interface{}{
			"common_name": commonName,
			"ttl":         ttl,
		})
	if err != nil {
		log.Printf("Error in createPKICertificate: %s", err)
		return PKIDataType {}, err
	}
	return PKIDataType {
		certificate: strings.TrimSpace(s1.Data["certificate"].(string)),
		issuingCA: strings.TrimSpace(s1.Data["issuing_ca"].(string)),
		privateKey: strings.TrimSpace(s1.Data["private_key"].(string)),
		privateKeyType: s1.Data["private_key_type"].(string),
		serialNumber: s1.Data["serial_number"].(string),
	}, nil
}

//
// Tests validating various workflows
//
// This is the first draft of the code. It is only POC (proof-of-concept) and learning exercise and will be cleaned up after the code review.
//
// test_workflow1() - tests the gRPC endpoints
// test_workflow2() - Testing client API calls, reads from the vault and un-marshals the results
// test_workflow3() - tests List() and Read() methods on the Vault
// test_workflow4() - creates a certificate and reads it for verification.
//

func test_workflow1() {
	log.Print("\n*********** Testing gRPC endpoints v1.0 - test_workflow1 **********\n")
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	} else {
		log.Printf("Connected to %s via grpc", address)
	}
	defer conn.Close()
	c := pb.NewSecretKeeperClient(conn)

	// Read a secret from the Vault
	var secretRequest pb.SecretRequest
	secretRequest.SecretPath = "secret/production/qa"
	r, err := c.SaySecret(context.Background(), &secretRequest)
	if err != nil {
		log.Fatalf("could not request a secret %s: %v", secretRequest.SecretPath, err)
	}
	log.Printf("\n\nSaySecret() returned: %s", r.Message)

	// Read the CA certificate from the Vault
	r1, err := c.SayCACertificate(context.Background(), &pb.CACertificateRequest{})
	if err != nil {
		log.Fatalf("could not request a CA certificate: %v", err)
	}
	log.Printf("\n\nRequested a CA certificate: \n%s", r1.Message)

	// Read the current CRL from the Vault
	r2, err := c.SayCurrentCRL(context.Background(), &pb.CurrentCRLRequest{})
	if err != nil {
		log.Fatalf("could not request a current CRL: %v", err)
	}
	log.Printf("\n\nRequested current CRL: \n%s", r2.Message)

	// Create the CA certificate
	type CreateCACertificateRequest struct {
		role string
		commonName string
		ttl string
	}
	var createCACertRequest pb.CreateCACertificateRequest
			createCACertRequest.Role = "peernova-dot-com"
			createCACertRequest.CommonName = "blah2.peernova.com"
			createCACertRequest.Ttl = "100h"

	r3, err := c.SayCreateCACertificate(context.Background(), &createCACertRequest)
	log.Printf("Result returned from SayCreateCACertificate: " +
			"\nSerial Number:	\n%s\nCertificate:		\n%s\nIssuingCA:	\n%s\nPrivateKeyType:%s - Private Key:\n%s",
		r3.SerialNumber, r3.Certificate, r3.IssuingCa, r3.PrivateKeyType, r3.PrivateKey)
	log.Print("\n********** End testing gRPC endpoints v1.0 **********\n")
}

func test_workflow2() {
	log.Print("\n\n********** Testing client API calls - test_workflow2 **********\n")
	// Test code for the Client package
	log.Printf("Starting Client configuration")
	cnf := api.DefaultConfig()
	if err := cnf.ReadEnvironment(); err != nil {
		log.Printf("Reading environment failed: %v", err)
	}
	client, err := api.NewClient(cnf)
	if err != nil {
		log.Printf("Creating a new Client failed: %v", err)
	}
	// Setting Vault address on the Client
	err = client.SetAddress(vaultAddr)
	if err != nil {
		log.Printf("Setting Vault address failed: %v", err)
	} else {
		log.Printf("Vault address set to %s", vaultAddr)
	}
	// Setting Vault token
	os.Setenv("VAULT_TOKEN", vaultToken)
	if err != nil {
		log.Printf("Setting Vault token failed: %v", err)
	} else {
		log.Printf("Vault token set to %s", vaultToken)
	}
	log.Printf("Starting HTTP request to get CA certificate")
	resp, err := http.Get("http://192.168.0.50:8200/v1/pki/cert/ca")
	if err != nil {
		// handle error
		log.Printf("Receiving certs failed: %v", err)
	}
	defer resp.Body.Close()
	jsonBodyString, err := ioutil.ReadAll(resp.Body)
	log.Printf("Response: %s", jsonBodyString)
	//
	m := make(map[string]interface{})
	err = json.Unmarshal(jsonBodyString, &m)
	if err != nil {
		log.Fatal(err)
	} else {
		t := m["data"].(map[string]interface{})
		cert := t["certificate"].(string)
		log.Printf("Certificate: \n%s", cert)
	}
	log.Print("\n********** End testing client configuration **********\n")
}

func test_workflow3() {
	log.Print("\n\n********** Testing HTTP APIs (Read, List) - test_workflow3 **********\n")
	vaultCFG := api.DefaultConfig()
	vaultCFG.Address = vaultAddr /*"http://127.0.0.1:8200"*/

	var err error
	vClient, err := api.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(vaultToken /*"6c7157eb-e909-decf-68ea-da41748afd8f"*/)
	vault := vClient.Logical()

	// Read environment
	err = vaultCFG.ReadEnvironment()
	if err != nil {
		log.Fatal("Reading Environment %s failed: %v", err)
	} else {
		log.Printf("Loading environment")
		log.Printf("VaultAddr: %s", vaultAddr)
		log.Printf("VaultToken: %s", vaultToken)
		log.Printf("Environment loaded")
	}

	type pkiParam struct {
		verb string
		pathParam string
		itemTitleParam string
		dataItemNameParam string
	}
	var pkiParams = [] pkiParam {
		{
			"Read",
			"pki/cert/ca",
			"CA certificate",
			"certificate",
		},
		{
			"Read",
			"pki/roles/peernova-dot-com",
			"Role peernova-dot-com [max_ttl]",
			"max_ttl",
		},
		{
			"Read",
			"pki/roles/peernova-dot-com",
			"Role peernova-dot-com [ttl]",
			"ttl",
		},
		{
			"List",
			"pki/certs",
			"Certificates",
			"keys",
		},
	}

	// Read secret, CA certificate, current CRL
	for _, p := range pkiParams {
		readPKIByVerb (p.verb, p.pathParam, p.itemTitleParam, p.dataItemNameParam, vault)
	}
	log.Print("\n********** End testing HTTP APIs (Read, List) **********\n")
}

func test_workflow4() {
	var newCertificateWithSN PKIDataType
	log.Print("\n\n********** Testing createPKICertificate - test_workflow4 **********\n")
	vaultCFG := api.DefaultConfig()
	vaultCFG.Address = vaultAddr /*"http://127.0.0.1:8200"*/

	var err error
	vClient, err := api.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(vaultToken /*"6c7157eb-e909-decf-68ea-da41748afd8f"*/)
	vault := vClient.Logical()	// Create a new certificate and read it by serial number for verification

	newCertificateWithSN, err = createPKICertificate (
		"peernova-dot-com",
		"blah2.peernova.com",
		"100h",
		vault)

	log.Printf("\nworkflow4(): New certificate written to the Vault:\n")
	log.Print(newCertificateWithSN.certificate)
	log.Printf("\nworkflow4(): New issuing CA written to the Vault:\n")
	log.Print(newCertificateWithSN.issuingCA)
	log.Printf("\nworkflow4(): New private Key written to the Vault:\n")
	log.Print(newCertificateWithSN.privateKey)
	log.Printf("\nworkflow4(): New serial Number written to the Vault:\n")
	log.Print(newCertificateWithSN.serialNumber)

	if newCertificateWithSN.serialNumber != "" {
		var retrievedCertificate string
		serialNumber := newCertificateWithSN.serialNumber

		// Read CA certificate again
		log.Print("\n\nworkflow3(): Read the certificate by its SN from the Vault again:")
		retrievedCertificate = readPKICertificateBySerialNumber (
			"pki/cert/",
			serialNumber,
			vault)

		var newCertificate = newCertificateWithSN.certificate
		var trimmedNewCertificateString = strings.TrimSpace(newCertificate)
		var trimmedRetrievedCertificate = strings.TrimSpace(retrievedCertificate)

		log.Printf("\nworkflow4(): Certificate retrieved from the Vault by readPKICertificateBySerialNumber:\n")
		log.Print("retrievedCertificate:",len(retrievedCertificate), "-", retrievedCertificate)
		log.Printf("\nworkflow4(): Certificate written to the Vault by writePKICertificate:\n")
		log.Print("writtenCertificate:",len(newCertificate), "-", newCertificate)
		log.Print(trimmedNewCertificateString)

		if strings.Compare(trimmedRetrievedCertificate, trimmedNewCertificateString) == 0 {
			log.Print("\nworkflow4(): The certificate written to the Vault was retrieved successfully.")
		} else {
			log.Print("Certificates did not match")
		}
	} else {
		log.Printf("\nworkflow4(): Writing to the Vault failed: %s", err.Error())
	}
	log.Print("\n********** End testing createPKICertificate **********\n")
}

func main() {
	// These workflows are used for testing functionality locally
	// when test framework is not available
	test_workflow1()
	test_workflow2()
	test_workflow3()
	test_workflow4()
}
