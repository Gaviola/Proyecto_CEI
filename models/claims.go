package models

import jwt "github.com/dgrijalva/jwt-go"

// Claims
/*
Estructura de los claims de un token JWT.
*/
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}
