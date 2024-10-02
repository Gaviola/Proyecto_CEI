package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	// "github.com/Gaviola/Proyecto_CEI_Back.git/internal/middlewares"
	"github.com/Gaviola/Proyecto_CEI_Back.git/internal/repositories"
	"github.com/Gaviola/Proyecto_CEI_Back.git/models"
	"github.com/go-chi/chi/v5"
)

// AdminRoutes
/*
Agrega las rutas de la API que requieren autenticación y permisos de administrador.
*/
func AdminRoutes(r chi.Router) {
	r.Route("/admin", func(r chi.Router) {
		// r.Use(middlewares.AuthMiddleware)  // Middleware de verificación de token
		// r.Use(middlewares.AdminMiddleware) // Middleware de verificación de admin

		// Rutas para usuarios
		r.Route("/users", func(r chi.Router) {
			r.Post("/", CreateUser)           // Crear un usuario
			r.Delete("/{userID}", DeleteUser) // Eliminar un usuario
			r.Patch("/{userID}", UpdateUser)  // Actualizar un usuario
			r.Get("/", GetUsers)              // Obtener todos los usuarios
			r.Get("/{userID}", GetUser)       // Obtener un usuario
			r.Put("/{userID}", VerifyUser)    // Verificar un usuario
		})

		// Rutas para tipos de ítems
		r.Route("/item-types", func(r chi.Router) {
			r.Post("/", createItemType)               // Crear un tipo de ítem
			r.Delete("/{itemTypeID}", DeleteItemType) // Eliminar un tipo de ítem
			r.Patch("/{itemTypeID}", UpdateItemType)  // Actualizar un tipo de ítem
			r.Get("/", GetItemTypes)                  // Obtener todos los tipos de ítems
			r.Get("/{itemTypeID}", GetItemType)       // Obtener un tipo de ítem
		})

		// Rutas para ítems
		r.Route("/items", func(r chi.Router) {
			r.Post("/", CreateItem)           // Crear un ítem
			r.Delete("/{itemID}", DeleteItem) // Eliminar un ítem
			r.Patch("/{itemID}", UpdateItem)  // Actualizar un ítem
			r.Get("/", GetItems)              // Obtener todos los ítems
			r.Get("/{itemID}", GetItem)       // Obtener un ítem
		})

		// Rutas para préstamos
		r.Route("/loans", func(r chi.Router) {
			r.Post("/", CreateLoan)           // Crear un préstamo
			r.Delete("/{loanID}", DeleteLoan) // Eliminar un préstamo
			r.Patch("/{loanID}", UpdateLoan)  // Actualizar un préstamo
			r.Get("/", GetLoans)              // Obtener todos los préstamos
			r.Get("/{loanID}", GetLoan)       // Obtener un préstamo
		})

		// Rutas para items de préstamo
		r.Route("/loan-items", func(r chi.Router) {
			r.Post("/", CreateLoanItem)               // Crear un ítem de préstamo
			r.Delete("/{loanItemID}", DeleteLoanItem) // Eliminar un ítem de préstamo
			r.Patch("/{loanItemID}", UpdateLoanItem)  // Actualizar un ítem de préstamo
			r.Get("/", GetLoanItems)                  // Obtener todos los ítems de préstamo
			r.Get("/{loanItemID}", GetLoanItem)       // Obtener un ítem de préstamo
		})
	})
}

// CreateUser
/*
Recibe los datos de un nuevo usuario,
verifica que los campos sean correctos
y los guarda en la base de datos
*/
func CreateUser(w http.ResponseWriter, r *http.Request) {
	// Crea un nuevo usuario a partir de los datos recibidos
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		// Maneja el error si los datos no son correctos
		http.Error(w, "Invalid user data", http.StatusBadRequest)
		return
	}
	// Verificar que el usuario no exista
	var existUser bool
	existUser, err = repositories.DBCheckUser(user.Email)
	if err != nil {
		http.Error(w, "Error checking user", http.StatusInternalServerError)
		return
	}
	if !existUser {
		// Guarda el nuevo usuario en la base de datos
		err = repositories.DBSaveUser(user)
		if err != nil {
			return
		}
		// Responde con el nuevo usuario creado
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(user)
		if err != nil {
			return
		}
	} else {
		http.Error(w, "User already exists", http.StatusBadRequest)
	}
}

// DeleteUser
/*
Recibe el id de un usuario y lo elimina de la base de datos
*/
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Captura el valor del parámetro userID de la URL
	userID := chi.URLParam(r, "userID")
	// Convierte el userID a un número entero, si es necesario
	id, err := strconv.ParseInt(userID, 10, 0)
	if err != nil {
		// Maneja el error si el userID no es un número válido
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	// Elimina el usuario de la base de datos
	err = repositories.DBDeleteUser(int(id))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
}

// UpdateUser
/*
Recibe los datos de un usuario y los actualiza en la base de datos
*/
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Captura el valor del parámetro userID de la URL
	userID := chi.URLParam(r, "userID")
	// Convierte el userID a un número entero, si es necesario
	id, err := strconv.ParseInt(userID, 10, 0)
	if err != nil {
		// Maneja el error si el userID no es un número válido
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	// busca el usuario en la base de datos
	user, err := repositories.DBGetUserByID(int(id))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Actualiza los datos del usuario con los datos recibidos
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		// Maneja el error si los datos no son correctos
		http.Error(w, "Invalid user data", http.StatusBadRequest)
		return
	}
}

// GetUsers
/*
Obtiene todos los usuarios de la base de datos
*/
func GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := repositories.DBGetAllUsers()
	if err != nil {
		return
	}
	// Responde con los usuarios encontrados
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		return
	}
}

// GetUser
/*
Obtiene un usuario de la base de datos
*/
func GetUser(w http.ResponseWriter, r *http.Request) {
	// Captura el valor del parámetro userID de la URL
	userID := chi.URLParam(r, "userID")
	// Convierte el userID a un número entero, si es necesario
	id, err := strconv.ParseInt(userID, 10, 0)
	if err != nil {
		// Maneja el error si el userID no es un número válido
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	user, err := repositories.DBGetUserByID(int(id))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Responde con el usuario encontrado
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		return
	}
}

// VerifyUser
/*
Recibe el id de un usuario y lo verifica
*/
func VerifyUser(w http.ResponseWriter, r *http.Request) {
	// Captura el valor del parámetro userID de la URL
	userID := chi.URLParam(r, "userID")
	// Convierte el userID a un número entero, si es necesario
	id, err := strconv.ParseInt(userID, 10, 0)
	if err != nil {
		// Maneja el error si el userID no es un número válido
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	// Verifica el usuario en la base de datos
	err = repositories.DBVerifyUser(int(id))
	if err != nil {
		http.Error(w, "Error while verifying the user", http.StatusNotFound)
		return
	}
	print(id) // Debug: DELETE LATER
}

// CreateItemType
/*
Recibe los datos de un nuevo tipo de item,
verifica que los campos sean correctos
y los guarda en la base de datos
*/
func createItemType(w http.ResponseWriter, r *http.Request) {
	
	var itemType models.ItemType

	err := json.NewDecoder(r.Body).Decode(&itemType)

	if err != nil {
		http.Error(w, "Invalid item type data", http.StatusBadRequest)
		return
	}

	err = repositories.DBSaveItemType(itemType)

	if err != nil {
		fmt.Println(err)
		return
	}
}

// DeleteItemType
/*
Recibe el id de un tipo de item y lo elimina de la base de datos
*/
func DeleteItemType(w http.ResponseWriter, r *http.Request) {
	
	itemTypeID := chi.URLParam(r, "itemTypeID")

	id, err := strconv.ParseInt(itemTypeID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item type ID", http.StatusBadRequest)
		return
	}

	err = repositories.DBDeleteItemType(int(id))

	if err != nil {
		http.Error(w, "Item type not found", http.StatusNotFound)
		return
	}
}

// UpdateItemType
/*
Recibe los datos de un tipo de item y los actualiza en la base de datos
*/
func UpdateItemType(w http.ResponseWriter, r *http.Request) {
	
	itemTypeID := chi.URLParam(r, "itemTypeID")

	id, err := strconv.ParseInt(itemTypeID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item type ID", http.StatusBadRequest)
		return
	}

	itemType, err := repositories.DBGetItemTypeByID(int(id))

	if err != nil {
		http.Error(w, "Item type not found", http.StatusNotFound)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&itemType)

	if err != nil {
		http.Error(w, "Invalid item type data", http.StatusBadRequest)
		return
	}
}

// GetItemTypes
/*
Obtiene todos los tipos de item de la base de datos
*/
func GetItemTypes(w http.ResponseWriter, r *http.Request) {
	
	itemTypes, err := repositories.DBShowItemTypes()

	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(itemTypes)

	if err != nil {
		return
	}
}

// GetItemType
/*
Obtiene un tipo de item de la base de datos
*/
func GetItemType(w http.ResponseWriter, r *http.Request) {
	
	itemTypeID := chi.URLParam(r, "itemTypeID")

	id, err := strconv.ParseInt(itemTypeID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item type ID", http.StatusBadRequest)
		return
	}

	itemType, err := repositories.DBGetItemTypeByID(int(id))

	if err != nil {
		http.Error(w, "Item type not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(itemType)

	if err != nil {
		return
	}
}

// CreateItem
/*
Recibe los datos de un nuevo item,
verifica que los campos sean correctos
y los guarda en la base de datos
*/
func CreateItem(w http.ResponseWriter, r *http.Request) {
	
	var item models.Item

	err := json.NewDecoder(r.Body).Decode(&item)

	if err != nil {
		http.Error(w, "Invalid item data", http.StatusBadRequest)
		return
	}

	err = repositories.DBSaveItem(item)

	if err != nil {
		fmt.Println(err)
		return
	}
}

// DeleteItem
/*
Recibe el id de un item y lo elimina de la base de datos
*/
func DeleteItem(w http.ResponseWriter, r *http.Request) {

	itemID := chi.URLParam(r, "itemID")

	id, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	err = repositories.DBDeleteItem(int(id))

	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}
}

// UpdateItem
/*
Recibe los datos de un item y los actualiza en la base de datos
*/
func UpdateItem(w http.ResponseWriter, r *http.Request) {
	
	itemID := chi.URLParam(r, "itemID")

	id, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	item, err := repositories.DBGetItemByID(int(id))

	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&item)

	if err != nil {
		http.Error(w, "Invalid item data", http.StatusBadRequest)
		return
	}
}

// GetItems
/*
Obtiene todos los items de la base de datos
*/
func GetItems(w http.ResponseWriter, r *http.Request) {
	
	items, err := repositories.DBShowItems()

	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(items)

	if err != nil {
		return
	}
}

// GetItem
/*
Obtiene un item de la base de datos
*/
func GetItem(w http.ResponseWriter, r *http.Request) {
	
	itemID := chi.URLParam(r, "itemID")

	id, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	item, err := repositories.DBGetItemByID(int(id))

	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(item)

	if err != nil {
		return
	}
}

// CreateLoan
/*
Recibe los datos de un nuevo prestamo,
verifica que los campos sean correctos
y los guarda en la base de datos
*/
func CreateLoan(w http.ResponseWriter, r *http.Request) {
	var loan models.Loan

	err := json.NewDecoder(r.Body).Decode(&loan)

	if err != nil {
		http.Error(w, "Invalid loan data", http.StatusBadRequest)
		return
	}

	err = repositories.DBSaveLoan(loan)

	if err != nil {
		fmt.Println(err)
		return
	}
}

// DeleteLoan
/*
Recibe el id de un prestamo y lo elimina de la base de datos
*/
func DeleteLoan(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	id, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan ID", http.StatusBadRequest)
		return
	}

	err = repositories.DBDeleteLoan(int(id))

	if err != nil {
		http.Error(w, "Loan not found", http.StatusNotFound)
		return
	}
}

// UpdateLoan
/*
Recibe los datos de un prestamo y los actualiza en la base de datos
*/
func UpdateLoan(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	id, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan ID", http.StatusBadRequest)
		return
	}

	loan, err := repositories.DBGetLoanByID(int(id))

	if err != nil {
		http.Error(w, "Loan not found", http.StatusNotFound)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&loan)

	if err != nil {
		http.Error(w, "Invalid loan data", http.StatusBadRequest)
		return
	}
}

// GetLoans
/*
Obtiene todos los prestamos de la base de datos
*/
func GetLoans(w http.ResponseWriter, r *http.Request) {
	
	loans, err := repositories.DBShowLoans()

	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(loans)

	if err != nil {
		return
	}

}

// GetLoan
/*
Obtiene un prestamo de la base de datos
*/
func GetLoan(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	id, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan ID", http.StatusBadRequest)
		return
	}

	loan, err := repositories.DBGetLoanByID(int(id))

	if err != nil {
		http.Error(w, "Loan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(loan)

	if err != nil {
		return
	}
}

// CreateLoanItem
/*
Recibe los datos de un nuevo item de prestamo,
verifica que los campos sean correctos
y los guarda en la base de datos
*/
func CreateLoanItem(w http.ResponseWriter, r *http.Request) {
	
	var loanItem models.LoanItem

	err := json.NewDecoder(r.Body).Decode(&loanItem)

	if err != nil {
		http.Error(w, "Invalid loan item data", http.StatusBadRequest)
		return
	}

	err = repositories.DBSaveLoanItem(loanItem)

	if err != nil {
		fmt.Println(err)
		return
	}
}

// DeleteLoanItem
/*
Recibe el id de un item de prestamo y lo elimina de la base de datos
*/
func DeleteLoanItem(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	lid, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan item ID", http.StatusBadRequest)
		return
	}

	itemID := chi.URLParam(r, "itemID")

	iid, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	err = repositories.DBDeleteLoanItem(int(lid), int(iid))

	if err != nil {
		http.Error(w, "Loan item not found", http.StatusNotFound)
		return
	}
	
}

// UpdateLoanItem
/*
Recibe los datos de un item de prestamo y los actualiza en la base de datos
*/
func UpdateLoanItem(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	lid, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan item ID", http.StatusBadRequest)
		return
	}

	itemID := chi.URLParam(r, "itemID")

	iid, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	loanItem, err := repositories.DBGetLoanItem(int(lid), int(iid))

	if err != nil {
		http.Error(w, "Loan item not found", http.StatusNotFound)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&loanItem)

	if err != nil {
		http.Error(w, "Invalid loan item data", http.StatusBadRequest)
		return
	}
}

// GetLoanItems
/*
Obtiene todos los items de prestamo de la base de datos
*/
func GetLoanItems(w http.ResponseWriter, r *http.Request) {
	
	loanItems, err := repositories.DBShowLoanItems()

	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(loanItems)

	if err != nil {
		return
	}
}

// GetLoanItem
/*
Obtiene un item de prestamo de la base de datos
*/
func GetLoanItem(w http.ResponseWriter, r *http.Request) {
	
	loanID := chi.URLParam(r, "loanID")

	lid, err := strconv.ParseInt(loanID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid loan item ID", http.StatusBadRequest)
		return
	}

	itemID := chi.URLParam(r, "itemID")

	iid, err := strconv.ParseInt(itemID, 10, 0)

	if err != nil {
		http.Error(w, "Invalid item ID", http.StatusBadRequest)
		return
	}

	loanItem, err := repositories.DBGetLoanItem(int(lid), int(iid))

	if err != nil {
		http.Error(w, "Loan item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(loanItem)

	if err != nil {
		return
	}
}
