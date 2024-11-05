package routes

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/repositories"
	"github.com/Gaviola/Proyecto_CEI_Back.git/models"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

// RegisterRoutes
/*
RegisterRoutes define las rutas para el registro de usuarios.
*/
func RegisterRoutes(r chi.Router) {
	r.Route("/register", func(r chi.Router) {
		r.Post("/user", RegisterUser) // registro manual
	})
}

// RegisterUser
/*
Recibe los datos de un nuevo usuario, verifica que los campos sean correctos y los guarda en la base de datos
*/
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	//Recibo los datos del usuario desde el frontend y los guardo en la base de datos
	newUser := models.RegisterUser{}
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verifico que no se encuentre ya registrado
	existingUser, err := repositories.DBGetUserByEmail(newUser.Email)
	if err != nil {
		http.Error(w, "Error checking email", http.StatusInternalServerError)
		return
	}
	if !existingUser.IsEmpty() {
		http.Error(w, "Email already in use", http.StatusConflict)
		return
	}

	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	userRegister := models.User{
		Name:      newUser.Name,
		Lastname:  newUser.Lastname,
		StudentId: newUser.StudentId,
		Email:     newUser.Email,
		Phone:     newUser.Phone,
		Role:      "student",
		Dni:       newUser.Dni,
		CreatorId: newUser.CreatorId,
		School:    newUser.School,
		Hash:      hash,
	}

	userRegister.IsVerified = false
	err = repositories.DBSaveUser(userRegister)
	if err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	// Creo el token JWT
	tokenString, err := CreateSessionToken(userRegister, 240)
	if err != nil {
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(map[string]string{
		"tokenJWT":    tokenString,
		"id":          strconv.Itoa(userRegister.ID),
		"role":        userRegister.Role,
		"username":    userRegister.Name,
		"lastname":    userRegister.Lastname,
		"email":       userRegister.Email,
		"student_id":  strconv.Itoa(userRegister.StudentId),
		"phone":       strconv.Itoa(userRegister.Phone),
		"dni":         strconv.Itoa(userRegister.Dni),
		"school":      userRegister.School,
		"is_verified": strconv.FormatBool(userRegister.IsVerified)})

	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}
