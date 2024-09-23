package repositories

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"github.com/Gaviola/Proyecto_CEI_Back.git/models"

	_ "github.com/lib/pq"
)

// connect
/*
Conecta a la base de datos y devuelve un puntero a la conexion.
Devuelve nil si hay un error en la conexion.
*/
func connect(isFacu bool) *sql.DB {
	var connStr string

	if isFacu {
		connStr = "host=localhost dbname=CEI user=fgaviola password=facu1234 sslmode=disable"
	} else {
		connStr = "host=localhost dbname=cei_db user=agus password=0811 sslmode=disable"
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		defer db.Close()
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
		return nil
	}

	return db
}

// DBExistUser
/*
Busca un usuario en la base de datos segun el hash de la contraseña y el username.
Devuelve el usuario correspondiente si el usuario existe.
Devuelve un usuario vacio si el usuario no existe o si hay un error en la base de datos.
*/
func DBExistUser(passHash []byte, user string) (models.User, error) {
	findUser := models.User{}
	db := connect(false)
	query := "SELECT * FROM users WHERE email = $1 AND hash = $2"
	result := db.QueryRow(query, user, passHash).Scan(&findUser.ID, &findUser.Name, &findUser.Lastname, &findUser.StudentId, &findUser.Email, &findUser.Phone, &findUser.Role, &findUser.Dni, &findUser.CreatorId, &findUser.School, &findUser.IsVerified, &findUser.Hash)

	if result != nil {
		return findUser, result
	}
	return findUser, nil
}

// DBGetUserByEmail
/*
Busca un usuario en la base de datos segun el email. Devuelve el usuario correspondiente si el usuario existe.
Devuelve un usuario vacio si el usuario no existe o si hay un error en la base de datos.
*/
func DBGetUserByEmail(email string) (models.User, error) {
	var user models.User
	db := connect(false)
	query := "SELECT * FROM users WHERE email = $1"
	err := db.QueryRow(query, email).Scan(&user.ID, &user.Name, &user.Lastname, &user.StudentId, &user.Email, &user.Phone, &user.Role, &user.Dni, &user.CreatorId, &user.School, &user.IsVerified, &user.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return user, nil
	}
	if err != nil {
		return user, err
	}
	return user, nil
}

// DBSaveUser
/*
Guarda un usuario en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBSaveUser(user models.User) error {
	db := connect(false)
	query := "INSERT INTO users (name, lastname, studentID, email, phone, role, DNI, creatorid, school, isverified, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
	_, err := db.Exec(query, user.Name, user.Lastname, user.StudentId, user.Email, user.Phone, user.Role, user.Dni, user.CreatorId, user.School, user.IsVerified, user.Hash)
	if err != nil {

		return err
	}
	return nil
}

// DBShowItemTypes
/*
Devuelve una lista con los tipos de items que hay en la base de datos.
*/
func DBShowItemTypes() ([]byte, error) {
	var itemTypes []models.ItemType

	db := connect(false)
	query := "SELECT * FROM typeitem"
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var itemType models.ItemType
		err := rows.Scan(&itemType.ID, &itemType.Name, &itemType.IsGeneric)
		if err != nil {
			log.Fatal(err)
		}
		itemTypes = append(itemTypes, itemType)
	}

	// Convertir a JSON
	jsonData, err := json.Marshal(itemTypes)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// DBShowItems
/*
Devuelve una lista con los items que hay en la base de datos en formato JSON.
*/
func DBShowItems() ([]byte, error) {
	var items []models.Item

	db := connect(false)
	query := "select it.id, it.name, e.code, e.price from item e join typeitem it on e.typeid = it.id;"

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item models.Item
		err := rows.Scan(&item.ID, &item.ItemType, &item.Code, &item.Price)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	// Convertir a JSON
	jsonData, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// DBSaveItemType
/*
Guarda un itemtype en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBSaveItemType(itemType models.ItemType) error {
	db := connect(false)
	query := "INSERT INTO typeitem (name, isgeneric) VALUES ($1, $2)"
	_, err := db.Exec(query, itemType.Name, itemType.IsGeneric)
	if err != nil {
		return err
	}
	return nil
}

// DBSaveItem
/*
Guarda un item en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBSaveItem(item models.Item) error {

	db := connect(false)
	query := "INSERT INTO item (typeid, code, price) VALUES ($1, $2, $3)"
	_, err := db.Exec(query, item.ItemType, item.Code, item.Price)
	if err != nil {
		return err
	}
	return nil
}

// DBUpdateItemType
/*
Actualiza un itemtype en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBUpdateItemType(itemType models.ItemType) error {
	db := connect(false)
	query := "UPDATE typeitem SET name = $1, isgeneric = $2 WHERE id = $3"
	_, err := db.Exec(query, itemType.Name, itemType.IsGeneric, itemType.ID)
	if err != nil {
		return err
	}
	return nil
}

// DBUpdateItem
/*
Actualiza un item en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBUpdateItem(item models.Item) error {
	db := connect(false)
	query := "UPDATE item SET typeid = $1, code = $2, price = $3 WHERE id = $4"
	_, err := db.Exec(query, item.ItemType, item.Code, item.Price, item.ID)
	if err != nil {
		return err
	}
	return nil
}

// DBShowLoans
/*
Devuelve una lista con los prestamos que hay en la base de datos en formato JSON.
*/
func DBShowLoans() ([]byte, error) {
	var loans []models.Loan

	db := connect(false)
	query := "SELECT * FROM loan"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var loan models.Loan
		err := rows.Scan(&loan.ID, &loan.Status, &loan.UserID, &loan.AdminID, &loan.CreationDate, &loan.EndingDate, &loan.ReturnDate, &loan.Observation, &loan.Price, &loan.PaymentMethod)
		if err != nil {
			return nil, err
		}
		loans = append(loans, loan)
	}

	// Convertir a JSON
	jsonData, err := json.Marshal(loans)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// DBSaveLoan
/*
Guarda un prestamo en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBSaveLoan(loan models.Loan) error {
	db := connect(false)
	query := "INSERT INTO loan (status, userid, adminid, creationdate, endingdate, returndate, observation, price, paymentmethod) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
	_, err := db.Exec(query, loan.Status, loan.UserID, loan.AdminID, loan.CreationDate, loan.EndingDate, loan.ReturnDate, loan.Observation, loan.Price, loan.PaymentMethod)
	if err != nil {
		return err
	}
	return nil
}

// DBUpdateLoan
/*
Actualiza un prestamo en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBUpdateLoan(loan models.Loan) error {
	db := connect(false)
	query := "UPDATE loan SET status = $1, userid = $2, adminid = $3, creationdate = $4, endingdate = $5, returndate = $6, observation = $7, price = $8, paymentmethod = $9 WHERE id = $10"
	_, err := db.Exec(query, loan.Status, loan.UserID, loan.AdminID, loan.CreationDate, loan.EndingDate, loan.ReturnDate, loan.Observation, loan.Price, loan.PaymentMethod, loan.ID)
	if err != nil {
		return err
	}
	return nil
}

// DBShowLoanItems
/*
Devuelve una lista con los items de un prestamo en formato JSON.
*/
func DBShowLoanItems(loanID int) ([]byte, error) {
	var loanItems []models.LoanItem

	db := connect(false)
	query := "SELECT * FROM loanitem WHERE loanid = $1"
	rows, err := db.Query(query, loanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var loanItem models.LoanItem
		err := rows.Scan(&loanItem.LoanID, &loanItem.ItemID)
		if err != nil {
			return nil, err
		}
		loanItems = append(loanItems, loanItem)
	}

	// Convertir a JSON
	jsonData, err := json.Marshal(loanItems)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// DBSaveLoanItem
/*
Guarda un item de un prestamo en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBSaveLoanItem(loanItem models.LoanItem) error {
	db := connect(false)
	query := "INSERT INTO loanitem (loanid, itemid) VALUES ($1, $2)"
	_, err := db.Exec(query, loanItem.LoanID, loanItem.ItemID)
	if err != nil {
		return err
	}
	return nil
}

// DBUpdateLoanItem
/*
Actualiza un item de un prestamo en la base de datos. Devuelve un error si hay un error en la base de datos.
*/
func DBUpdateLoanItem(loanItem models.LoanItem) error {
	db := connect(false)
	query := "UPDATE loanitem SET loanid = $1, itemid = $2 WHERE loanid = $3 AND itemid = $4"
	_, err := db.Exec(query, loanItem.LoanID, loanItem.ItemID, loanItem.LoanID, loanItem.ItemID)
	if err != nil {
		return err
	}
	return nil
}



