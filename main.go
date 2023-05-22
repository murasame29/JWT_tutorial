package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// ペイロード部のシークレットキー
var SECRET = []byte("super-secret-auth-key")

// JWT生成用のAPIキー
var api_key = "hogehoge"

// JWTTokenを生成する
func CreateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenStr, err := token.SignedString(SECRET)

	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	return tokenStr, nil
}

// JWTを検証する関数
// HTTPhandlerが返される
func ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(t *jwt.Token) (interface{}, error) {
				_, ok := t.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("not authorized"))
				}
				return SECRET, nil
			})
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("not authorized" + err.Error()))
			}

			if token.Valid {
				next(w, r)
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("not authorized"))
		}
	})
}

// 生成したJWTを返す Handler(Api_keyが必須)
func GetJWT(w http.ResponseWriter, r *http.Request) {
	if r.Header["Access"] != nil {
		if r.Header["Access"][0] == api_key {
			token, err := CreateJWT()
			if err != nil {
				return
			}

			fmt.Fprint(w, token)
		}
	}
}

// JWTが必要なAPIのHandler
func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Super secret area")
}

func main() {
	//メインコンテンツ
	http.Handle("/home", ValidateJWT(home))
	//JWT を生成して返す (Api_keyが必須)
	http.HandleFunc("/jwt", GetJWT)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe :", err)
	}
}
