package routes

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
		r.Post("/createLoan", createLoan)   // Crear un préstamo
		r.Delete("/cancelLoan", cancelLoan) // Cancelar prestamo
		r.Get("/getLoans", getLoans)        // Obtener préstamos
		r.Get("/getItems", getItems)        // Obtener ítems
		r.Get("/getItemTypes", getItemTypes) // Obtener tipos de ítems
		r.Patch("/updateUser", updateUser)  // Actualizar datos del usuario
		r.Get("/getUser", getUser)          // Obtener datos del usuario
	})
}

// CreaLoan
/*
Crea un préstamo de un ítem para el usuario.
*/
func createLoan(w http.ResponseWriter, r *http.Request) {
	// Obtengo el ID del usuario desde el token JWT
	userID, err := getTokenId(r)

	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Decodifico el json en un map para obtener el campo "itemType"
	var data map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		http.Error(w, "Error al deserializar en map:", http.StatusBadRequest)
		return
	}

	// Variable para guardar "itemType"
	var itemType int
	if it, ok := data["itemType"].(float64); ok { // JSON numbers are unmarshalled as float64
		itemType = int(it)
	} else {
		http.Error(w, "Campo 'itemType' no encontrado o no es un int", http.StatusBadRequest)
		return
	}

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

	// Return ID of first available item
	loanItem := models.LoanItem{
		LoanID: int(loanID),
		ItemID: availableItems[0].ID,
	}

	err = repositories.DBSaveLoanItem(loanItem)

	if err != nil {
		fmt.Println(err)
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
	idUser, err := getTokenId(r)

	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	loan := models.Loan{}
	err = json.NewDecoder(r.Body).Decode(&loan)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	loan.UserID = idUser

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
	id, err := getTokenId(r)

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

	items, err := repositories.DBShowAvailableItems()
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

// GetItemTypes
/*
Obtiene todos los tipos de ítems que hay prestar a un usuario.
*/
func getItemTypes(w http.ResponseWriter, r *http.Request) {
	var itemTypes []models.ItemType

	itemTypes, err := repositories.DBShowItemTypes()
	if err != nil {
		http.Error(w, "Error getting item types", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(itemTypes)
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
	id, err := getTokenId(r)

	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	updatedUser := models.User{}
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

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

	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

}

// GetTokenId
/*
Obtiene el ID del usuario a partir del token JWT.
*/
func getTokenId(r *http.Request) (int, error) {
	var jwtKey []byte
	jwtKey, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		return 0, err
	}

	// Obtengo el ID del usuario desde el token JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return 0, fmt.Errorf("no Authorization header provided")
	}

	// Split the header to get the token part
	tokenString := strings.Split(authHeader, "Bearer ")[1]

	// Parse the token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return 0, err
	}

	if !token.Valid {
		return 0, fmt.Errorf("invalid token")
	}

	return claims.ID, nil
}
