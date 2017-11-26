package authentication

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/charly3pins/jwt-example/models"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("./private.rsa")
	if err != nil {
		log.Println("Error reading private key:", err)
	}

	publicBytes, err := ioutil.ReadFile("./public.rsa.pub")
	if err != nil {
		log.Println("Error reading public key:", err)
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Println("Error parsing to private key:", err)
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Println("Error parsing to public key:", err)
	}
}

func GenerateJWT(user models.User) string {
	claims := models.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "JWT example",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	jwt, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("Error signing token:", err)
	}

	return jwt
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Fprintf(w, "Error decoding user %s", err)
		return
	}

	if user.Name == "charly" && user.Password == "charly" {
		user.Password = ""
		user.Role = "admin"

		token := GenerateJWT(user)
		rt := models.ResponseToken{
			Token: token,
		}
		jsonResult, err := json.Marshal(rt)
		if err != nil {
			fmt.Fprintf(w, "Error marshaling jwt %s", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResult)
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "User or password incorrect")
	}
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			validationError := err.(*jwt.ValidationError)
			switch validationError.Errors {
			case jwt.ValidationErrorExpired:
				fmt.Fprintln(w, "Token expired")
				return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Fprintln(w, "Token signature invalid")
				return
			default:
				fmt.Fprintln(w, "Invalid token")
				return
			}
		}
	}

	if token.Valid {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "Welcome")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Invalid token")
	}
}
