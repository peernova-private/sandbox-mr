package trustedentityCommon

import (
	"log"
	vaultapi "github.com/hashicorp/vault/api"
	"strings"
	"os"
	"github.com/peernova-private/cuneiform/src/gore/config"
)

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
	log.Printf("************ Initializing Vault")
	var v *config.Vault = InitConfig()
	// Initialize the Vault
	vaultCFG := vaultapi.DefaultConfig()
	vaultCFG.Address = v.Get("trustedentity.vaultaddr").(string) //conf.VaultAddr /*"http://127.0.0.1:8200"*/

	var err error
	vClient, err := vaultapi.NewClient(vaultCFG)
	if err != nil {
		log.Fatal("Instantiating Vault client failed: %v", err)
	}

	vClient.SetToken(v.Get("trustedentity.vaultaddr").(string)) //conf.VaultToken /*"7269298c-1542-8bad-ade8-6c11402da30e"*/
	vault := vClient.Logical()

	// Read environment
	err = vaultCFG.ReadEnvironment()
	if err != nil {
		log.Fatal("Reading Environment failed: %v", err)
	} else {
		log.Printf("Environment read and loaded")
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
	log.Printf("InitConfig().************ Initializing Configuration ****************")
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
func ReadVaultPKIProperty (path string, itemTitle string, dataItemName string, vaultPar *vaultapi.Logical) (string, error) {
	var dataItemValue string
	log.Printf("Reading Vault PKI property - '%s' from path: '%s'", itemTitle, path)
	s, err := vaultPar.Read(path)
	if err != nil {
		log.Fatal("Reading Vault '" + itemTitle + " from " + path + " %s failed: %v ", err)
	} else {
		var ok bool
		dataItemValue, ok = s.Data[dataItemName].(string)
		if !ok {
			log.Fatalf("PKI Property is not a string %v", err)
		}
		log.Printf("The Vault PKI '%s' property - '%s' from path: '%s' = '%s'", itemTitle, dataItemName, path, dataItemValue)
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
