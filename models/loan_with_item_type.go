package models

import "database/sql"

// Loan
/*
Estructura de datos de un préstamo.
*/
type LoanWithItemType struct {
	ID            int            `json:"id"`
	Status        string         `json:"status"`
	UserID        int            `json:"borrowerName"`
	AdminID       int            `json:"deliveryResponsible"`
	CreationDate  sql.NullString `json:"deliveryDate"`
	EndingDate    sql.NullString `json:"endingDate"`
	ReturnDate    sql.NullString `json:"returnDate"`
	Observation   sql.NullString `json:"observation"`
	Price         float64        `json:"amount"`
	PaymentMethod sql.NullString `json:"paymentMethod"`
	ItemType	  string         `json:"itemType"`
}