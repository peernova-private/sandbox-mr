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
	pb "github.com/peernova-private/trustedentity/protobuf"
	api "github.com/hashicorp/vault/api"
	"encoding/json"
)

const (
	address     = "localhost:50051"
	defaultName = "world"
	vaultAddr = "http://192.168.0.50:8200"
	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
)

/*
	TBD
*/
func readPKIByVerb (verb string, path string, itemTitle string, dataItemName string, vaultPar *api.Logical) {
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
			log.Printf("The '%s' ['%s']: \n%s", itemTitle, dataItemName, dataItemValue)
		}
	}
	return
}

/*
	TBD
*/
func readPKIBySerialNumber (path string, itemTitle string, dataItemName string, serialNumber string, vaultPar *api.Logical) string {
	var err error
	var s *api.Secret
	var retValue string

	fullPath := path + serialNumber
	log.Printf("\n\nReading Vault '%s': '%s'", itemTitle, fullPath)
	s, err = vaultPar.Read(fullPath)

	if err != nil {
		log.Fatalf("Reading Vault '%s' from '%s' failed: %v", itemTitle, fullPath, err)
	} else {
		if s == nil {
			log.Fatalf("Vault '%s' was nil", itemTitle)
		} else {
			dataItemValue, err1 := s.Data[dataItemName].(string)
			if !err1 {
				log.Fatalf("PKI Property %s is not a string %v", dataItemName, err1)
			}
			retValue = dataItemValue
			log.Printf("The '%s' ['%s']: \n%s", itemTitle, dataItemName, dataItemValue)
		}
	}
	return retValue
}

func workflow1() {
	log.Print("\n********** Test gRPC endpoints **********\n")
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	} else {
		log.Printf("Connected to %s via grpc", address)
	}
	defer conn.Close()
	c := pb.NewSecretKeeperClient(conn)
	// Contact the server and print out its response.
	name := defaultName
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	r, err := c.SaySecret(context.Background(), &pb.SecretRequest{Name: name})
	if err != nil {
		log.Fatalf("could not request a secret: %v", err)
	}
	log.Printf("Requesting a secret (SaySecret - secret/production/qa): %s", r.Message)

	r1, err := c.SayCACertificate(context.Background(), &pb.CACertificateRequest{})
	if err != nil {
		log.Fatalf("could not request a CA certificate: %v", err)
	}
	log.Printf("Requesting a CA certificate (SayCACertificate - pki/cert/ca): %s", r1.Message)

	r2, err := c.SayCurrentCRL(context.Background(), &pb.CurrentCRLRequest{})
	if err != nil {
		log.Fatalf("could not request a current CRL: %v", err)
	}
	log.Printf("Requesting current CRL (SayCurrentCRL - pki/cert/crl): %s", r2.Message)
}

func workflow2() {
	log.Print("\n\n********** Test client configuration **********\n")
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
	log.Printf("********* Client test complete *********\n\n")
}
func workflow3() {
	log.Print("\n\n********** Test HTTP APIs (Read, List) **********\n")
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
		//{
		//	"Read",
		//	"secret/production/qa",
		//	"secret",
		//	"value",
		//},
		//{
		//	"Read",
		//	"pki/cert/crl",
		//	"current CRL",
		//	"certificate",
		//},
		//{
		//	"List",
		//	"pki/roles",
		//	"Roles",
		//	"keys",
		//},
		//{
		//	"Read",
		//	"pki/config/urls",
		//	"Config URLs/Issuing Certificates",
		//	"issuing_certificates",
		//},
		//{
		//	"Read",
		//	"pki/config/urls",
		//	"Config URLs/Distribution Points",
		//	"crl_distribution_points",
		//},
	}

	//var pkiParams2 = [] pkiParam {
	//	{
	//		"List",
	//		"pki/certs",
	//		"Certificates",
	//		"keys",
	//	},
	//	{
	//		"Read",
	//		"pki/cert/ca",
	//		"CA certificate",
	//		"certificate",
	//	},
	//}

	// Read secret, CA certificate, current CRL
	for _, p := range pkiParams {
		readPKIByVerb (p.verb, p.pathParam, p.itemTitleParam, p.dataItemNameParam, vault)
	}

	// Create a new certificate and read it by serial number for verification
	var s1 *api.Secret
	log.Printf("\n\nWriting certificate to the Vault:")
	c := vClient.Logical()
	s1, err = c.Write("pki/issue/peernova-dot-com",
		map[string]interface{}{
			"common_name":  "blah2.peernova.com",
			"ttl":"100h",
		})
	if err == nil {
		serialNumber := s1.Data["serial_number"]
		log.Printf("\nSerial Number:\n")
		log.Print(serialNumber)
		log.Printf("\nCertificate:\n")
		log.Print(s1.Data["certificate"])

		// Read CA certificate again
		log.Print("\n\nRead the certificate by its SN from the Vault again:")
		certificate := readPKIBySerialNumber (
			"pki/cert/",
			"Certificate",
			"certificate",
			serialNumber.(string),
			vault)
		log.Printf("\nCertificate:\n")
		log.Print(certificate)
	} else {
		log.Printf("Writing to the Vault failed: %s", err.Error())
	}
}

func main() {
	workflow1()
	workflow2()
	workflow3()
}
