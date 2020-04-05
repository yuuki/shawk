package command

import (
	"github.com/yuuki/shawk/db"
	"golang.org/x/xerrors"
)

type CreateSchemeParam struct {
	DB db.Opt
}

func CreateScheme(param *CreateSchemeParam) error {
	logger.Infof("Connecting postgres ...")

	db, err := db.New(&param.DB)
	if err != nil {
		return xerrors.Errorf("postgres initialize error: %w", err)
	}

	logger.Infof("Connected postgres ...")

	logger.Infof("Creating postgres schema ...")

	if err := db.CreateSchema(); err != nil {
		return err
	}

	return nil
}
