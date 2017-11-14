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

//go:generate protoc -I ../trustedentity --go_out=plugins=grpc:../trustedentity ../trustedentity/trustedentity.proto

package main

import (
	"log"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/peernova-private/sandbox-mr/trustedentity/protobuf"
	"google.golang.org/grpc/reflection"
	vaultapi "github.com/hashicorp/vault/api"
	"strings"
	//"github.com/hashicorp/consul/logger"
)

const (
	port = ":50051"
	vaultAddr = "http://192.168.0.50:8200"
	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
	serverVersion = "3.0"
)

type PKIDataType struct {
	certificate string
	issuingCA string
	privateKey string
	privateKeyType string
	serialNumber string
}

func initVault() *vaultapi.Logical {
	vaultCFG := vaultapi.DefaultConfig()
	vaultCFG.Address = vaultAddr /*"http://127.0.0.1:8200"*/

	var err error
	vClient, err := vaultapi.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(vaultToken /*"7269298c-1542-8bad-ade8-6c11402da30e"*/)
	vault := vClient.Logical()

	// Read environment
	err = vaultCFG.ReadEnvironment()
	if err != nil {
		log.Fatal("Reading Environment failed: %v", err)
	} else {
		log.Printf("Environment loaded")
	}
	return vault
}

/*
	This function reads a property element.

	path - 			the Vault path, e.g. "pki/cert"
	serialNumber -	serial number of the retrieved certificate
	vaultPar -		pointer to the Vault interface

	Example:
		const caCertPath = "pki/cert/ca"
		const itemTitle = "CA certificate"
		const dataItemName = "certificate"
		caCertificate := readVaultPKIProperty (caCertPath,  itemTitle, dataItemName, vault)

	Returns - a certificate in string format
*/
func readVaultPKIProperty (path string, itemTitle string, dataItemName string, vaultPar *vaultapi.Logical) (string, error) {
	var dataItemValue string
	log.Printf("Reading Vault PKI property - '%s' from path: '%s'", itemTitle, path)
	s, err := vaultPar.Read(path)
	if err != nil {
		log.Fatal("Reading Vault %s from %s failed: %v ", itemTitle, path, err)
	} else {
		var ok bool
		dataItemValue, ok = s.Data[dataItemName].(string)
		if !ok {
			log.Fatalf("PKI Property is not a string %v", err)
		}
		log.Printf("The Vault PKI '%s' property - '%s' from path: '%s' = '%s'", itemTitle, dataItemName, path, dataItemValue)
	}
	if err != nil {
		log.Fatal("Reading item %s from Vault failed: %s", itemTitle, err)
	}
	return dataItemValue, err
}

/*
	The function creates and returns a new certificate.

	role - 			the role for which the certificate is created
	commonName -	the common name
	ttl - 			time to live for the certificate
	vaultPar -		pointer to the Vault interface

	Returns - the following type PKIDataType struct:
					{
					certificate string
					issuingCA string
					privateKey string
					privateKeyType string
					serialNumber string
					}
*/
func createPKICertificate (
		role string,
		commonName string,
		ttl string,
		vaultPar *vaultapi.Logical) (PKIDataType, error) {
	var s1 *vaultapi.Secret
	var err error

	log.Printf("\n\nWriting certificate to the Vault in createPKICertificate:")
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

// SecretKeeperServer is used to implement trustedentity.SecretKeeperServer.
type secretKeeperServer struct{

}

// SaySecret implements trustedentity.SecretKeeperServer.SaySecret service
func (s *secretKeeperServer) SaySecret(ctx context.Context, in *pb.SecretRequest) (*pb.SecretReply, error) {
	//log.Printf("Server Step SaySecret v" + serverVersion )
	const itemTitle = "secret"
	const dataItemName = "value"
	var vault = initVault()
	secret, err := readVaultPKIProperty (in.SecretPath, itemTitle, dataItemName, vault)
	if err != nil {
		log.Printf("Failed to read a secret: %v", err)
		return &pb.SecretReply{}, err
	}
	return &pb.SecretReply{
		secret}, err
}

// SayCACertificate implements trustedentity.SecretKeeperServer.SayCACertificate service
func (s *secretKeeperServer) SayCACertificate(ctx context.Context, in *pb.CACertificateRequest) (*pb.CACertificateReply, error) {
	//log.Printf("Server Step SayCACertificate v" + serverVersion)
	const caCertPath = "pki/cert/ca"
	const itemTitle = "CA certificate"
	const dataItemName = "certificate"
	var vault = initVault()
	caCertificate, err := readVaultPKIProperty (caCertPath,  itemTitle, dataItemName, vault)
	if err != nil {
		log.Printf("Failed to read a CA certificate: %v", err)
		return &pb.CACertificateReply{}, err
	}
	log.Printf("CA Certificate: %s", caCertificate)
	return &pb.CACertificateReply{
		Message: caCertificate}, err
}

// SayCurrentCRL implements trustedentity.SecretKeeperServer.SayCurrentCRL service
func (s *secretKeeperServer) SayCurrentCRL(ctx context.Context, in *pb.CurrentCRLRequest) (*pb.CurrentCRLReply, error) {
	//log.Printf("Server Step SayCurrentCRL v" + serverVersion)
	const caCertPath = "pki/cert/crl"
	const itemTitle = "current CRL"
	const dataItemName = "certificate"
	var vault = initVault()
	currentCRL, err := readVaultPKIProperty (caCertPath, itemTitle, dataItemName, vault)
	if err != nil {
		log.Printf("Failed to read current CRL: %v", err)
		return &pb.CurrentCRLReply{}, err
	}
	return &pb.CurrentCRLReply{
		Message: currentCRL}, err
}

// SayCreateCACertificateReply implements trustedentity.SecretKeeperServer.SayCreateCACertificateReply service
/*
	// The request message for the CreateCACertificate request.
	message CreateCACertificateRequest {
	  string role = 1;
	  string commonName = 2;
	  string ttl = 3;
	}

	// The response message containing the CreateCACertificate response
	message CreateCACertificateReply {
	  string certificate = 1;
	  string issuing_ca = 2;
	  string private_key = 3;
	  string private_key_type = 4;
	  string serial_number = 5;
	}
 */
func (s *secretKeeperServer) SayCreateCACertificate(ctx context.Context, in *pb.CreateCACertificateRequest) (*pb.CreateCACertificateReply, error) {
	//log.Printf("Server Step SayCreateCACertificate v" + serverVersion)
	var vault = initVault()
	currentCreateCACertificate, err := createPKICertificate (in.Role, in.CommonName, in.Ttl, vault)
	if err != nil {
		log.Printf("Failed to create a new CA certificate: %v", err)
		return &pb.CreateCACertificateReply{}, err
	}
	return &pb.CreateCACertificateReply{
		Certificate: currentCreateCACertificate.certificate,
		IssuingCa: currentCreateCACertificate.issuingCA,
		PrivateKey: currentCreateCACertificate.privateKey,
		PrivateKeyType: currentCreateCACertificate.privateKeyType,
		SerialNumber: currentCreateCACertificate.serialNumber,
		}, nil
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	log.Println("Server NewServer() version " + serverVersion +"")
	pb.RegisterSecretKeeperServer(s, &secretKeeperServer{})
	log.Println("Server RegisterSecretKeeperServer()")
	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Server reflection.Register(s)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
