package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"go-sso/tokens"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

type TokenRequest struct {
	Token string `json:"token"`
}

type TokenResponse struct {
	Token string `json:"token"`
	Msg string `json:"msg"`
}

func main() {
	// database
	connStr := "user=postgres dbname=go_sso password=Postgres!23456 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	layout := "Jan 2, 2006 at 3:04pm (MST)"
	tm, _ := time.Parse(layout, "Feb 4, 2034 at 6:05pm (PST)")
	log.Println("time", tm.Unix())

	// jwt
	secretKey := []byte("secret")
	jwtStr, err := tokens.GenerateToken(secretKey, &jwt.RegisteredClaims{
		Issuer:    "tea@gmail.com",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Second)),
	})
	if err != nil {
		panic(err)
	}
	log.Println(jwtStr)

	// router
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Route("/v1", func(r chi.Router) {
		r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello"))
		})

		r.Post("/parse-jwt", func(w http.ResponseWriter, r *http.Request) {
			decoder := json.NewDecoder(r.Body)
			var tokenReq TokenRequest
			err := decoder.Decode(&tokenReq)
			if err != nil {
				panic(err)
			}
			_, err = jwt.Parse(tokenReq.Token, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("wrong signing method: %s", t.Header["alg"])
				}

				return secretKey, nil
			})
			if err != nil {
				if errors.Is(err, jwt.ErrTokenExpired) {
					jwtStr, err := tokens.GenerateToken(secretKey, &jwt.RegisteredClaims{
						Issuer:    "tea@gmail.com",
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					})
					if err != nil {
						panic(err)
					}
					tokenRes := TokenResponse{
						Token: jwtStr,
						Msg: "Token expired, return new token",
					}

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					encoder := json.NewEncoder(w)
					encoder.Encode(tokenRes)
					return
				} else {
					panic(err)
				}
			}
			log.Println("Parsing Token successfully")
		})
	})

	err = http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}
}
