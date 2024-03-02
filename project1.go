package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type JWK struct {
	Kid string	`json:"kid"`
	Alg string	`json:"alg"`
	Kty string	`json:"kty"`
	Use string	`json:"use"`
	N string	`json:"n"`
	E string	`json:"e"`
	Exp int		`json:"exp"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type Header struct {
	Alg string	`json:"alg"`
	Typ string	`json:"typ"`
	Kid string	`json:"kid"`
}

type Payload struct {
	Data string	`json:"data"`
	Exp int		`json:"exp"`
}



func main()  {

	//Set up the server multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", handleAuth)
	mux.HandleFunc("/.well-known/jwks.json", handleJWKS)

	//Listen for incoming requests on port 8080
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}



func generateKeyPairs(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, e := rsa.GenerateKey(rand.Reader, bits)
	if e != nil {
		return nil, nil, e
	}
	
	//Validate the private key
	e = privateKey.Validate()
	if e != nil {
		return nil, nil, e
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, e
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	bits := 2048
	//Check for the expired query parameter
	hasExpired := r.URL.Query().Has("expired")
	//1. Create the JWK
		//Generate keys
		privateKey, publicKey, e := generateKeyPairs(bits)
		if e != nil {
			log.Fatal("Error generating keys")
		}
		//Create a JWK from the public key
		newJWK := createJWK(publicKey, hasExpired)

		//pem of keys - for testing
		/*************************/
		// privateKeyPem := &pem.Block {
		// 	Type: "PRIVATE KEY",
		// 	Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		// }

		// privateKeyFile, _ := os.Create("private_key.pem")
		// pem.Encode(privateKeyFile, privateKeyPem)
		// privateKeyFile.Close()
		// publicKeyPem := &pem.Block{
		// 	Type: "PUBLIC KEY",
		// 	Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		// }
		// publicKeyFile, _ := os.Create("public_key.pem")
		// pem.Encode(publicKeyFile, publicKeyPem)
		// privateKeyFile.Close()
		/*************************/


	//2. Add the JWK to the jwks.json file
	
		//Open the JSON file
		file, e := os.OpenFile("jwks.json", os.O_RDWR|os.O_CREATE, 0644)
		if e != nil {
			log.Fatal("Error open jwks.json")
		}
		defer file.Close()

		//Read the contents of the file
		fileData, e := io.ReadAll(file)
		if e != nil {
			log.Fatal("Error reading the jwks.json file")
		}

		//Read the contents as JWKS
		var jwks JWKS
		json.Unmarshal(fileData, &jwks)

		//Add the new JWK
		jwks.Keys = append(jwks.Keys, newJWK)

		//Convert the new JWKS into JSON
		newData, e := json.MarshalIndent(jwks,"", "")
		if e != nil {
			log.Fatal("Error converting new JWKS to JSON")
		}

		_, error := file.WriteAt(newData, 0)
		if error != nil {
			log.Fatal("Error writing new JWKS to JSON file", error)
		}

	//3. Create the JWT
		JWT := createJWT(newJWK.Kid, newJWK.Exp, privateKey)
		// fmt.Printf(JWT)
		w.Write([]byte(JWT))
		
}

func createJWT(kid string, expiredTime int, privateKey *rsa.PrivateKey ) (string) {

	//Create a header and payload
	header := Header{Alg:"RS256", Typ: "JWT", Kid: kid}
	payload := Payload{Data:"Example data", Exp: expiredTime}

	//Convert the header and payload to a JSON format
 
	headJSON, e := json.Marshal(header)
	if e != nil {
		log.Fatal("Error converting JWT Header to JSON")
	}
	payloadJSON, e := json.Marshal(payload)
	if e != nil {
		log.Fatal("Error converting JWT Payload to JSON")
	}

	//Encode the header and payload into base64
	encodedHeader := strings.TrimRight(base64.URLEncoding.EncodeToString(headJSON), "=")
	encodedPayload := strings.TrimRight(base64.URLEncoding.EncodeToString(payloadJSON), "=")

	signatureMessage := encodedHeader + "." + encodedPayload
	h := sha256.New()
	h.Write([]byte(signatureMessage))
	d := h.Sum(nil)

	//Create the signature
	signature, e := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, d)
	if e != nil {
		log.Fatal("Error creating JWT signature")
	}

	//Create the actual JWT
	encodedSignature := strings.TrimRight(base64.URLEncoding.EncodeToString(signature), "=")
	return encodedHeader + "." + encodedPayload + "." + encodedSignature
}

func createJWK(publicKey *rsa.PublicKey, isExpired bool) (JWK) {
	kid := uuid.New()
	
	encodedN := strings.TrimRight(base64.URLEncoding.EncodeToString(publicKey.N.Bytes()), "=")
	
	eVal := big.NewInt(int64(publicKey.E))
	
	encodedE := strings.TrimRight(base64.URLEncoding.EncodeToString(eVal.Bytes()), "=")

	expireTime := int(time.Now().Unix())

	//Add a day
	if !isExpired {
		expireTime += 86400
	}
	
	//Generate a JWK entry
	newJWK := JWK{Kid: kid.String(), Alg: "RS256", Kty: "RSA", Use: "sig", N: encodedN, E: encodedE, Exp: expireTime} 
	return newJWK
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET is allowed", http.StatusMethodNotAllowed)
		return
	}

	//Open the JSON file
	file, e := os.Open("jwks.json")
	if e != nil {
		log.Fatal("Error reading JSON file")
	}
	defer file.Close()

	fileData, e := io.ReadAll(file)
	if e != nil {
		log.Fatal("Error reading JSON file")
	}

	var jwks JWKS
	var unexpiredJWKS JWKS
	err := json.Unmarshal(fileData, &jwks)
	if err != nil {
		log.Fatal("Error reading jwks.json into struct")
	}

	currentTime := int(time.Now().Unix())
	for _, element := range jwks.Keys {
		if element.Exp > currentTime {
			unexpiredJWKS.Keys = append(unexpiredJWKS.Keys, element)
		}
	}

	returnJWKS, e := json.Marshal(unexpiredJWKS)
	if e != nil {
		log.Fatal("Error converting to JSOn")
	}

	// w.Header().Set("Content-Type", "application/json")
	// w.WriteHeader(http.StatusOK)
	_, error := w.Write(returnJWKS)
	if error != nil {
		log.Fatal("Error writing header")
	}
}







