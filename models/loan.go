package models

// Loan
/*
Estructura de datos de un préstamo.
*/
type Loan struct {
	ID            int
	Status        string
	UserID        int
	AdminID       int
	CreationDate  string
	EndingDate    string
	ReturnDate    string
	Observation   string
	Price         float64
	PaymentMethod string
}
