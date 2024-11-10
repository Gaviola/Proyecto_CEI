package routes

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/repositories"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/services"
	"github.com/Gaviola/Proyecto_CEI_Back.git/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

// LoginRoutes
/*
LoginRoutes define las rutas para el login de usuarios.
*/
func LoginRoutes(r chi.Router) {
	r.Route("/login", func(r chi.Router) {
		r.Post("/user", LoginUser)     // Login con email y contraseña
		r.Post("/google", LoginGoogle) // Login con Google
		r.Post("/JWT", LoginJWT)       // Login con JWT
	})
	r.Route("/reset-password", func(r chi.Router) {
		r.Post("/", RequestPasswordReset) // Solicitar restablecimiento de contraseña
		r.Post("/{token}", ResetPassword) // Restablecer contraseña
	})
}

// LoginJWT
/*
LoginJWT permite a un usuario autenticarse con un token JWT.
*/
func LoginJWT(w http.ResponseWriter, r *http.Request) {
	var jwtKey []byte
	jwtKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		http.Error(w, "Error al decodificar la llave secreta", http.StatusInternalServerError)
		return
	}

	// Obtener el token del header Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Falta el header Authorization", http.StatusUnauthorized)
		return
	}

	// Verificar que el formato sea "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Formato de autorización inválido", http.StatusUnauthorized)
		return
	}

	tokenStr := parts[1]

	// Parsear y validar el token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
		return
	}

	//Busco al usuario en la base de datos en funcion del id dentro del token
	userID := claims.ID
	if err != nil {
		http.Error(w, "ID de usuario inválido", http.StatusInternalServerError)
		return
	}

	var user models.User
	user, err = repositories.DBGetUserByID(userID)
	if err != nil {
		http.Error(w, "Error de servidor", http.StatusInternalServerError)
		return
	}

	// Enviar el token en la respuesta junto con los datos del usuario
	err = json.NewEncoder(w).Encode(map[string]string{
		"id":          strconv.Itoa(user.ID),
		"role":        user.Role,
		"username":    user.Name,
		"lastname":    user.Lastname,
		"email":       user.Email,
		"student_id":  strconv.Itoa(user.StudentId),
		"phone":       strconv.Itoa(user.Phone),
		"dni":         strconv.Itoa(user.Dni),
		"school":      user.School,
		"is_verified": strconv.FormatBool(user.IsVerified),
	})

	if err != nil {
		http.Error(w, "No se puedo enviar el Token", http.StatusInternalServerError)
		return
	}

}

// LoginUser
/*
LoginUser permite a un usuario autenticarse con email y contraseña.
*/
func LoginUser(w http.ResponseWriter, r *http.Request) {
	var creds models.Credentials
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Peticion invalida", http.StatusBadRequest)
		return
	}

	// Busca el usuario en la base de datos segun el mail
	user, err = repositories.DBGetUserByEmail(creds.Username)
	if err != nil {
		http.Error(w, "Error de servidor en la busqueda del usuario", http.StatusInternalServerError)
		return
	}
	hashedPassword := user.Hash

	// Compara la contraseña ingresada con la contraseña hasheada en la base de datos
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(creds.Password))
	if err != nil {
		http.Error(w, "Contraseña ingresada incorrecta", http.StatusUnauthorized)
		return
	}

	var tokenString string
	tokenString, err = CreateSessionToken(user, 240)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Enviar el token en la respuesta junto con los datos del usuario
	err = json.NewEncoder(w).Encode(map[string]string{
		"tokenJWT":    tokenString,
		"id":          strconv.Itoa(user.ID),
		"role":        user.Role,
		"username":    user.Name,
		"lastname":    user.Lastname,
		"email":       user.Email,
		"student_id":  strconv.Itoa(user.StudentId),
		"phone":       strconv.Itoa(user.Phone),
		"dni":         strconv.Itoa(user.Dni),
		"school":      user.School,
		"is_verified": strconv.FormatBool(user.IsVerified),
	})

	if err != nil {
		http.Error(w, "No se puedo enviar el Token", http.StatusInternalServerError)
		return
	}

}

// CreateSessionToken
/*
Crea un token de sesion para el usuario recibido
*/
func CreateSessionToken(user models.User, sessionTime int) (string, error) {
	if !user.IsEmpty() {
		// Genera un token JWT
		expirationTime := time.Now().Add(time.Duration(sessionTime) * time.Minute)
		claims := &models.Claims{
			Username: user.Name,
			Role:     user.Role,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		// utilizar llave secreta para firmar el token
		var secretKey []byte
		secretKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
		if err != nil {
			return "", err
		}
		key := string(secretKey)
		if key == "" {
			return "", errors.New("la llave secreta está vacía")
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			return "", errors.New("no se pudo generar el token")
		}

		return tokenString, nil
	}

	return "", errors.New("el usuario no puede estar vacío")
}

// LoginGoogle
/*
LoginGoogle permite a un usuario autenticarse con Google.
*/
func LoginGoogle(w http.ResponseWriter, r *http.Request) {
	// Routes for the application
	http.HandleFunc("/", services.HandleMain)
	http.HandleFunc("/login-gl", services.HandleGoogleLogin)
	http.HandleFunc("/callback-gl", func(w http.ResponseWriter, r *http.Request) {
		response, err := services.CallBackFromGoogle(w, r)
		if err != nil {
			http.Error(w, "Error en la autenticación con Google", http.StatusInternalServerError)
			return
		}

		// Parse the response from Google
		var googleUser models.GoogleUser
		err = json.Unmarshal(response, &googleUser)
		if err != nil {
			http.Error(w, "Error en la autenticación con Google", http.StatusInternalServerError)
			return
		}

		// Check if the user exists in the database
		var user models.User
		user, err = repositories.DBGetUserByEmail(googleUser.Email)

		if err != nil {
			http.Error(w, "Error de servidor", http.StatusInternalServerError)
			return
		}

		var tokenString string
		// Si el usuario no existe, lo creo
		if !(user.IsEmpty()) {
			newUser := models.User{
				Name:       googleUser.Email,
				IsVerified: false,
			}

			err = repositories.DBSaveUser(newUser)
			if err != nil {
				http.Error(w, "Error guardando el usuario", http.StatusInternalServerError)
				return
			}

			if err != nil {
				http.Error(w, "Error creando el usuario", http.StatusInternalServerError)
				return
			}

			tokenString, err = CreateSessionToken(newUser, 240)

			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			// Envio el token del nuevo usuario
			err = json.NewEncoder(w).Encode(map[string]string{
				"tokenJWT":    tokenString,
				"id":          strconv.Itoa(user.ID),
				"role":        user.Role,
				"username":    user.Name,
				"lastname":    user.Lastname,
				"email":       user.Email,
				"student_id":  strconv.Itoa(user.StudentId),
				"phone":       strconv.Itoa(user.Phone),
				"dni":         strconv.Itoa(user.Dni),
				"school":      user.School,
				"is_verified": strconv.FormatBool(user.IsVerified)})
			if err != nil {
				http.Error(w, "No se puedo enviar el Token", http.StatusInternalServerError)
				return
			}
		}

		// Si existe, envio el token
		err = json.NewEncoder(w).Encode(map[string]string{"tokenJWT": tokenString})
		if err != nil {
			http.Error(w, "No se puedo enviar el Token", http.StatusInternalServerError)
			return
		}
	})

}

func RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	//Recibo el mail del usuario y lo guardo en un usuario temporal
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// busco al usuario en base al mail
	var foundUser models.User
	foundUser, err = repositories.DBGetUserByEmail(user.Email)
	if err != nil {
		http.Error(w, "Error de servidor", http.StatusInternalServerError)
		return
	}
	if foundUser.IsEmpty() {
		http.Error(w, "Usuario no registrado", http.StatusUnauthorized)
		return
	} else {
		//Genero un token para el usuario
		var token string
		token, err := generateResetToken(foundUser)
		if err != nil {
			http.Error(w, "Error al generar el token", http.StatusInternalServerError)
			return
		}
		//err = sendPasswordResetEmail(foundUser.Email, token)
		fmt.Print("Token: ", token)
		if err != nil {
			http.Error(w, "Error al enviar el mail", http.StatusInternalServerError)
			return
		}
	}

}

func generateResetToken(user models.User) (string, error) {
	expirationTime := time.Now().Add(20 * time.Minute)
	claims := &models.Claims{
		Username: strconv.Itoa(user.ID),
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// utilizar llave secreta para firmar el token
	var secretKey []byte
	secretKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		return "", errors.New("no se pudo decodificar la llave secreta")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", errors.New("no se pudo generar el token")
	}
	return tokenString, nil
}

func sendPasswordResetEmail(toEmail string, token string) error {
	password := os.Getenv("SMTP_PASSWORD")
	mailTo := "facundo.gaviola@gmail.com"
	mailFrom := "facundo.gaviola@gmail.com"
	resetURL := "http://localhost:8080/reset-password?token=" + token
	body := fmt.Sprintf("Click here to reset your password: %s", resetURL)

	// Configura el servidor SMTP (hay que cambiar el mailTo y mailFrom)
	m := gomail.NewMessage()
	m.SetHeader("From", mailFrom)
	m.SetHeader("To", mailTo)
	m.SetHeader("Subject", "Restablecimiento de contraseña")
	m.SetBody("text/plain", body)

	// Conexión con el servidor SMTP. (Deberiamos utilizar un mail del cei o algo asi. Guardar la contraseña en una variable de entorno)
	d := gomail.NewDialer("smtp.gmail.com", 587, "facundo.gaviola@gmail.com", password)

	// Enviar el correo.
	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	var secretKey []byte
	secretKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		http.Error(w, "No se pudo decodificar la llave secreta", http.StatusInternalServerError)
		return
	}
	// Obtener el token de la URL.
	tokenString := chi.URLParam(r, "token")

	// Parsear y verificar el token.
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// El token es válido, obtenemos el ID del usuario desde los claims.
	userID, err := strconv.Atoi(claims.Username)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	// Ahora puedes permitir al usuario cambiar la contraseña.
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Hashear la nueva contraseña y actualizarla en la base de datos.
	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	// Actualiza la contraseña en la base de datos.
	user := models.User{
		Hash: hash,
	}
	err = repositories.DBUpdateUser(userID, user)
	if err != nil {
		http.Error(w, "Could not update password", http.StatusInternalServerError)
		return
	}

	// Responder éxito.
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Password has been reset successfully",
	})
	if err != nil {
		return
	}
}
