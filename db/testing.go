package db

import (
	"github.com/DATA-DOG/go-sqlmock"
)

// NewTestDB creates a database instance for mock.
func NewTestDB() (*DB, sqlmock.Sqlmock, error) {
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, mock, err
	}

	return &DB{db}, mock, nil
}
