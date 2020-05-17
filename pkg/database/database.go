package database

import (
	"database/sql"
)

// Connect to database
func Connect() (db *sql.DB, err error) {
	dbDriver := "mysql"
	dbUser := "i9t4r5x4"
	dbPass := "8V0a6O7s"
	dbName := "payadme"
	db, err = sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		return nil, err
	}

	return db, nil
}
