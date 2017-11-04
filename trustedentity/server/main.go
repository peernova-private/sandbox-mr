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
	pb "github.com/peernova-private/trustedentity/protobuf"
	"google.golang.org/grpc/reflection"
	vaultapi "github.com/hashicorp/vault/api"
)

const (
	port = ":50051"
	vaultAddr = "http://192.168.0.50:8200"
	vaultToken = "6c7157eb-e909-decf-68ea-da41748afd8f"
)

// Globally declared vault variable
var vault *vaultapi.Logical = initVault()

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

func readVaultPKIProperty (path string, itemTitle string, dataItemName string, vaultPar *vaultapi.Logical) string {
	var dataItemValue string
	log.Printf("Reading Vault %s: %s", itemTitle, path)
	s, err := vaultPar.Read(path)
	if err != nil {
		log.Fatal("Reading Vault %s from %s failed: %v ", itemTitle, path, err)
	} else {
		dataItemValue, err1 := s.Data[dataItemName].(string)
		if !err1 {
			log.Fatalf("PKI Property is not a string %v", err1)
		}
		log.Printf("The %s ['%s']: %s", itemTitle, dataItemName, dataItemValue)
	}
	if s == nil {
		log.Fatal("Vault %s was nil", itemTitle)
	}
	return dataItemValue
}

// SecretKeeperServer is used to implement trustedentity.SecretKeeperServer.
type secretKeeperServer struct{

}

// SaySecret implements trustedentity.SecretKeeperServer.SaySecret service
func (s *secretKeeperServer) SaySecret(ctx context.Context, in *pb.SecretRequest) (*pb.SecretReply, error) {
	log.Printf("Server Step SaySecret in.Name = " + in.Name)
	retResult := readVaultPKIProperty ("secret/production/qa", "secret", "value", vault)
	return &pb.SecretReply{Message: "Secret Requested: " + in.Name + " result:" + retResult}, nil
}

// SayCACertificate implements trustedentity.SecretKeeperServer.SayCACertificate service
func (s *secretKeeperServer) SayCACertificate(ctx context.Context, in *pb.CACertificateRequest) (*pb.CACertificateReply, error) {
	log.Printf("Server Step SayCACertificate")
	caCertificate := readVaultPKIProperty ("pki/cert/ca", "CA certificate", "certificate", vault)
	log.Printf("CA Certificate: %s", caCertificate)
	return &pb.CACertificateReply{Message: "CACertificate Requested: " + caCertificate}, nil
}

// SayCurrentCRL implements trustedentity.SecretKeeperServer.SayCurrentCRL service
func (s *secretKeeperServer) SayCurrentCRL(ctx context.Context, in *pb.CurrentCRLRequest) (*pb.CurrentCRLReply, error) {
	log.Printf("Server Step SayCurrentCRL")
	currentCRL := readVaultPKIProperty ("pki/cert/crl", "current CRL", "certificate", vault)
	return &pb.CurrentCRLReply{Message: "CurrentCRL Requested: " + currentCRL}, nil
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	log.Println("Server NewServer() version 1.5")
	pb.RegisterSecretKeeperServer(s, &secretKeeperServer{})
	log.Println("Server RegisterSecretKeeperServer()")
	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Server reflection.Register(s)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
