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

package main //trustedentityServer

import (
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/peernova-private/sandbox-mr/trustedentity/protobuf"
	//cm "github.com/peernova-private/sandbox-mr/trustedentity/common"
	"google.golang.org/grpc/reflection"
	"github.com/peernova-private/cuneiform/src/gore/config"
	"net"
	vaultapi "github.com/hashicorp/vault/api"
	"strings"
	"os"
)

//const (
//	port = ":50051"
//	vaultAddr = "http://192.168.0.50:8200"
//	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
//	serverVersion = "2.5"
//)

type PKIDataType struct {
	Certificate string
	IssuingCA string
	PrivateKey string
	PrivateKeyType string
	SerialNumber string
}

type Config struct {
	GrpcAddress string // = "localhost:50051"
	DefaultName string //= "world"
	Port string //=":50051"
	VaultAddr string //= "http://192.168.0.50:8200"
	VaultToken string // = "6c7157eb-e909-decf-68ea-da41748afd8f"
	ServerVersion string // = "3.0"
}

const (
	Port 		= "trustedentity.port"
	GrpcAddress = "trustedentity.grpcAddress"
	DefaultName = "trustedentity.defaultName"
	VaultAddr 	= "trustedentity.vaultAddr"
	VaultToken 	= "trustedentity.vaultToken"
	ServerVersion = "trustedentity.serverVersion"
	RelConfPath	= "/conf/trustedentity.toml"
)

func InitVault() *vaultapi.Logical {
	// Initialize configuration parameters
	// which are read from a *.toml file
	var v *config.Vault = InitConfig()
	// Initialize the Vault
	vaultCFG := vaultapi.DefaultConfig()
	vaultCFG.Address = v.Get("trustedentity.vaultaddr").(string) //conf.VaultAddr /*"http://127.0.0.1:8200"*/

	var err error
	vClient, err := vaultapi.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(v.Get("trustedentity.vaulttoken").(string)) //conf.VaultToken /*"7269298c-1542-8bad-ade8-6c11402da30e"*/
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

func InitConfig() *config.Vault {
	v := config.NewVault("trustedentity")
	//v.SetDefault(Port, ":50051", "Default port number")
	v.SetDefault(Port, "", "Default port number")
	v.SetDefault(GrpcAddress, "", "Default gRPC address")
	v.SetDefault(DefaultName, "", "Default scope name")
	v.SetDefault(VaultAddr, "", "Default Vault IP")
	v.SetDefault(VaultToken, "", "Default vault access token")
	v.SetDefault(ServerVersion, "", "Default server version")

	pwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Printf("InitConfig().Current Directory: %s", pwd)
	var fullConfPath = pwd + RelConfPath
	if _, err := os.Stat(fullConfPath); os.IsNotExist(err) {
		log.Printf("Warning: configuration file not found at: %s", fullConfPath)
	}
	log.Printf("InitConfig().Config File Path: %s\n", fullConfPath)
	v.AddConfigFilePath(fullConfPath)
	v.ReadViperConfig()
	var port = v.Get("trustedentity.port")
	var grpcAddress = v.Get("trustedentity.grpcaddress")
	var defaultName = v.Get("trustedentity.defaultname")
	var vaultAddr = v.Get("trustedentity.vaultaddr")
	var vaultToken = v.Get("trustedentity.vaulttoken")
	var serverVersion = v.Get("trustedentity.serverversion")
	log.Printf("InitConfig().Port: %s", port)
	log.Printf("InitConfig().GrpcAddress: %s", grpcAddress)
	log.Printf("InitConfig().DefaultName: %s", defaultName)
	log.Printf("InitConfig().VaultAddr: %s", vaultAddr)
	log.Printf("InitConfig().VaultToken: %s", vaultToken)
	log.Printf("InitConfig().ServerVersion: %s", serverVersion)
	return v
}

/*
	The function reads a property element.

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
func ReadVaultPKIProperty (path string, itemTitle string, dataItemName string, vaultPar *vaultapi.Logical) (string, error) {
	var dataItemValue string
	log.Printf("Reading Vault PKI property - '%s' from path: '%s'", itemTitle, path)
	s, err := vaultPar.Read(path)
	if err != nil {
		log.Printf("Error: Reading Vault '"+itemTitle+" from "+path+" %s failed: %v ", err)
		return "", err
	}
	var ok bool
	dataItemValue, ok = s.Data[dataItemName].(string)
	if !ok {
		log.Printf("Error: PKI Property is not a string %v", err)
		return "", err
	}
	log.Printf("The Vault PKI '%s' property - '%s' from path: '%s' = '%s'", itemTitle, dataItemName, path, dataItemValue)
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
					certificate interface {}
					issuingCA interface {}
					privateKey interface {}
					privateKeyType interface {}
					serialNumber interface {}
					}
*/
func CreatePKICertificate (
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
		Certificate: strings.TrimSpace(s1.Data["certificate"].(string)),
		IssuingCA: strings.TrimSpace(s1.Data["issuing_ca"].(string)),
		PrivateKey: strings.TrimSpace(s1.Data["private_key"].(string)),
		PrivateKeyType: s1.Data["private_key_type"].(string),
		SerialNumber: s1.Data["serial_number"].(string),
	}, nil
}


// SecretKeeperServer is used to implement trustedentity.SecretKeeperServer.
type secretKeeperServer struct {
	myVault *vaultapi.Logical
}

/*
 GetVault -
		the first caller initializes the vault and stores the reference to it in the struct
		each subsequent caller verifies if the myVault element has been initialized
			and if true, then just returns the myVault value

		Returns - myVault value (a reference to the vault)
*/
func (s *secretKeeperServer) GetVault() (*vaultapi.Logical) {
	var secretServer secretKeeperServer
	var vault = secretServer.myVault
	if secretServer.myVault == nil {
		secretServer.myVault = InitVault()
		vault = secretServer.myVault
	}
	return vault
}

// SaySecret implements trustedentity.SecretKeeperServer.SaySecret service
func (s *secretKeeperServer) SaySecret(ctx context.Context, in *pb.SecretRequest) (*pb.SecretReply, error) {
	const itemTitle = "secret"
	const dataItemName = "value"
	var vault = s.GetVault()
	log.Printf("Calling ReadVaultPKIProperty() - path: %s, itemTitle: %s, itemName: %s", in.SecretPath, itemTitle, dataItemName)

	secret, err := ReadVaultPKIProperty (in.SecretPath, itemTitle, dataItemName, vault)
	if err != nil {
		log.Printf("Failed to read a secret: %v", err)
		return &pb.SecretReply{}, err
	}
	return &pb.SecretReply{
		secret}, err
}

// SayCACertificate implements trustedentity.SecretKeeperServer.SayCACertificate service
func (s *secretKeeperServer) SayCACertificate(ctx context.Context, in *pb.CACertificateRequest) (*pb.CACertificateReply, error) {
	const caCertPath = "pki/cert/ca"
	const itemTitle = "CA certificate"
	const dataItemName = "certificate"
	var vault = s.GetVault()

	caCertificate, err := ReadVaultPKIProperty (caCertPath,  itemTitle, dataItemName, vault)
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
	const caCertPath = "pki/cert/crl"
	const itemTitle = "current CRL"
	const dataItemName = "certificate"
	var vault = s.GetVault()

	currentCRL, err := ReadVaultPKIProperty (caCertPath, itemTitle, dataItemName, vault)
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
	var vault = s.GetVault()

	currentCreateCACertificate, err := CreatePKICertificate (in.Role, in.CommonName, in.Ttl, vault)
	if err != nil {
		log.Printf("Failed to create a new CA certificate: %v", err)
		return &pb.CreateCACertificateReply{}, err
	}
	return &pb.CreateCACertificateReply{
		Certificate: currentCreateCACertificate.Certificate,
		IssuingCa: currentCreateCACertificate.IssuingCA,
		PrivateKey: currentCreateCACertificate.PrivateKey,
		PrivateKeyType: currentCreateCACertificate.PrivateKeyType,
		SerialNumber: currentCreateCACertificate.SerialNumber,
	}, nil
}

func main() {
	var v *config.Vault = InitConfig()
	var v1 = v.Get("trustedentity.port")
	var v2 = v.Get("trustedentity.grpcaddress")
	var v3 = v.Get("trustedentity.defaultname")
	var v4 = v.Get("trustedentity.vaultaddr")
	var v5 = v.Get("trustedentity.vaulttoken")
	var v6 = v.Get("trustedentity.serverversion")
	log.Printf("Config parameters retrieved: %s, %s, %s, %s, %s, %s", v1,v2,v3,v4,v5,v6)

	log.Printf("Configuration token:%s, addr:%s, server version:%s",
		v.Get("trustedentity.vaulttoken"),
		v.Get("trustedentity.vaultaddr"),
		v.Get("trustedentity.serverversion"))

	lis, err := net.Listen("tcp", v.Get("trustedentity.port").(string))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	log.Printf("Server NewServer() version %v", v6)
	pb.RegisterSecretKeeperServer(s, &secretKeeperServer{})
	log.Println("Server RegisterSecretKeeperServer()")
	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Server reflection.Register(s)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
