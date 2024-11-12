package routes

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	// "github.com/Gaviola/Proyecto_CEI_Back.git/internal/middlewares"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/middlewares"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/repositories"
	"github.com/Gaviola/Proyecto_CEI_Back.git/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
)

func UserRoutes(r chi.Router) {
	r.Route("/user", func(r chi.Router) {
		r.Use(middlewares.AuthMiddleware) // Middleware de verificación de token

		// Rutas para usuarios
		r.Route("/{userID}", func(r chi.Router) {
			r.Post("/createLoan", createLoan)   // Crear un préstamo
			r.Delete("/cancelLoan", cancelLoan) // Cancelar prestamo
			r.Get("/getLoans", getLoans)        // Obtener préstamos
			r.Get("/getItems", getItems)        // Obtener ítems
			r.Patch("/updateUser", updateUser)  // Actualizar datos del usuario
			r.Get("/getUser", getUser)          // Obtener datos del usuario

		})
	})
}

// CreaLoan
/*
Crea un préstamo de un ítem para el usuario.
*/
func createLoan(w http.ResponseWriter, r *http.Request) {
	var jwtKey []byte
	jwtKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		http.Error(w, "Error al decodificar la llave secreta", http.StatusInternalServerError)
		return
	}

	// Obtengo el ID del usuario desde el token JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "No Authorization header provided", http.StatusUnauthorized)
		return
	}

	// Split the header to get the token part
	tokenString := strings.Split(authHeader, "Bearer ")[1]

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key (replace with your actual secret key)
		return jwtKey, nil
	})

	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Extract the user ID from the token claims
	var userID int
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID = claims["ID"].(int)
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Decodifico el JSON recibido
	var itemType int
	err = json.NewDecoder(r.Body).Decode(&itemType)

	// Verifico que haya al menos un item en la BD con el itemType recibido
	availableItems, err := repositories.DBShowAvailableItemsByItemType(itemType)
	if err != nil {
		http.Error(w, "Error al buscar items disponibles", http.StatusInternalServerError)
		return
	}

	if len(availableItems) == 0 {
		http.Error(w, "No hay items disponibles con el tipo de item recibido", http.StatusBadRequest)
		return
	}

	//Obtengo el precio del item
	itemPrice := availableItems[0].Price

	// Completo los campos faltantes
	loan := models.Loan{
		UserID:        userID,
		Status:        "Pending",
		AdminID:       0,
		CreationDate:  sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true},
		ReturnDate:    sql.NullString{String: "", Valid: false},
		EndingDate:    sql.NullString{String: "", Valid: false},
		Observation:   sql.NullString{String: "", Valid: false},
		Price:         itemPrice,
		PaymentMethod: sql.NullString{String: "", Valid: false},
	}

	var loanID int64
	loanID, err = repositories.DBSaveLoan(loan)

	if err != nil {
		return
	}

	// Enviar id del prestamo creado
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]int64{"loanID": loanID})
	if err != nil {
		return
	}

}

// CancelLoan
/*
Cancela un préstamo de un ítem para el usuario.
*/
func cancelLoan(w http.ResponseWriter, r *http.Request) {
	idUser := chi.URLParam(r, "userID")

	loan := models.Loan{}
	err := json.NewDecoder(r.Body).Decode(&loan)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	loan.UserID, err = strconv.Atoi(idUser)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	err = repositories.DBDeleteLoan(loan.ID)
	if err != nil {
		http.Error(w, "Error deleting loan", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetLoans
/*
Obtiene todos los préstamos del usuario.
*/
func getLoans(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	id, err := strconv.Atoi(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	loans, err := repositories.DBGetLoansByUserID(id)
	if err != nil {
		http.Error(w, "Error getting loans", http.StatusInternalServerError)
		return
	}
	// Devolver los préstamos en formato JSON
	err = json.NewEncoder(w).Encode(loans)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

}

// GetItems
/*
Obtiene todos los ítems disponibles para prestar a un usuario.
*/
func getItems(w http.ResponseWriter, r *http.Request) {
	var items []models.Item

	items, err := repositories.DBGetAvailableItems()
	if err != nil {
		http.Error(w, "Error getting items", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(items)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

}

// UpdateUser
/*
Actualiza los datos del usuario. Datos como ID o email no se pueden modificar.
*/
func updateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	updatedUser := models.User{}
	err := json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	//Chequeo que no se intente modificar ID o email
	if updatedUser.ID != id || updatedUser.Email != "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = repositories.DBUpdateUser(id, updatedUser)
	if err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

// GetUser
/*
Obtiene los datos del usuario.
*/
func getUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	id, err := strconv.Atoi(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := repositories.DBGetUserByID(id)
	if err != nil {
		http.Error(w, "Error getting user", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(user)

}
