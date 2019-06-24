package db

import (
	"github.com/DATA-DOG/go-sqlmock"
)

// NewTestDB creates a database instance for mock.
func NewTestDB() (*DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		panic(err)
	}
	return &DB{db}, mock
}
