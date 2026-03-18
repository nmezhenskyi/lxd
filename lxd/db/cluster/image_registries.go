package cluster

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"

	"github.com/canonical/lxd/lxd/db/query"
	"github.com/canonical/lxd/shared/api"
)

// Code generation directives.
//
//go:generate -command mapper lxd-generate db mapper -t image_registries.mapper.go
//go:generate mapper reset -i -b "//go:build linux && cgo && !agent"
//
//go:generate mapper stmt -e image_registry objects table=image_registries
//go:generate mapper stmt -e image_registry objects-by-ID table=image_registries
//go:generate mapper stmt -e image_registry objects-by-Name table=image_registries
//go:generate mapper stmt -e image_registry objects-by-Builtin table=image_registries
//go:generate mapper stmt -e image_registry id table=image_registries
//go:generate mapper stmt -e image_registry create table=image_registries
//go:generate mapper stmt -e image_registry update table=image_registries
//go:generate mapper stmt -e image_registry delete-by-Name table=image_registries
//go:generate mapper stmt -e image_registry rename table=image_registries
//
//go:generate mapper method -i -e image_registry GetMany table=image_registries
//go:generate mapper method -i -e image_registry GetOne table=image_registries
//go:generate mapper method -i -e image_registry ID table=image_registries
//go:generate mapper method -i -e image_registry Exists table=image_registries
//go:generate mapper method -i -e image_registry Create table=image_registries
//go:generate mapper method -i -e image_registry Update table=image_registries
//go:generate mapper method -i -e image_registry DeleteOne-by-Name table=image_registries
//go:generate mapper method -i -e image_registry Rename talbe=image_registries
//go:generate goimports -w image_registries.mapper.go
//go:generate goimports -w image_registries.interface.mapper.go

// ImageRegistry is the database representation of an [api.ImageRegistry].
type ImageRegistry struct {
	ID          int64
	Name        string `db:"primary=yes"`
	Description string `db:"coalesce=''"`
	Protocol    ImageRegistryProtocol
	Builtin     bool
}

// ImageRegistryFilter contains fields upon which an image registry can be filtered.
type ImageRegistryFilter struct {
	ID      *int64
	Name    *string
	Builtin *bool
}

// ImageRegistryProtocol represents the types of supported image registry protocols.
//
// This type implements the [sql.Scanner] and [driver.Value] interfaces to automatically handle
// conversion between API constants and their int64 representation in the database.
// When reading from the database, int64 values are converted back to their constant type.pick
// When writing to the database, API constants are converted to their int64 representation.
type ImageRegistryProtocol string

const (
	protocolSimpleStreams int64 = iota // Image registry protocol "SimpleStreams".
	protocolLXD                        // Image registry protocol "LXD".
)

// ScanInteger implements [query.IntegerScanner] for [ImageRegistryProtocol].
func (p *ImageRegistryProtocol) ScanInteger(protocolCode int64) error {
	switch protocolCode {
	case protocolSimpleStreams:
		*p = api.ImageRegistryProtocolSimpleStreams
	case protocolLXD:
		*p = api.ImageRegistryProtocolLXD
	default:
		return fmt.Errorf("Unknown image registry protocol `%d`", protocolCode)
	}

	return nil
}

// Scan implements [sql.Scanner] for [ImageRegistryProtocol]. This converts the database integer value back into the correct API constant or returns an error.
func (p *ImageRegistryProtocol) Scan(value any) error {
	return query.ScanValue(value, p, false)
}

// Value implements [driver.Value] for [ImageRegistryProtocol]. This converts the API constant into its integer database representation or throws an error.
func (p ImageRegistryProtocol) Value() (driver.Value, error) {
	switch p {
	case api.ImageRegistryProtocolSimpleStreams:
		return protocolSimpleStreams, nil
	case api.ImageRegistryProtocolLXD:
		return protocolLXD, nil
	}

	return nil, fmt.Errorf("Invalid image registry protocol %q", p)
}

// GetImageRegistryConfig returns associated config of the existing image registry with the given name.
func GetImageRegistryConfig(ctx context.Context, tx *sql.Tx, name string) (map[string]string, error) {
	registry, err := GetImageRegistry(ctx, tx, name)
	if err != nil {
		return nil, fmt.Errorf("Failed loading image registry: %w", err)
	}

	config, err := imageRegistryConfigGet(ctx, tx, registry.ID)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// CreateImageRegistryConfig creates config for a new image registry with the given name.
func CreateImageRegistryConfig(ctx context.Context, tx *sql.Tx, name string, config map[string]string) error {
	id, err := GetImageRegistryID(ctx, tx, name)
	if err != nil {
		return err
	}

	err = imageRegistryConfigAdd(ctx, tx, id, config)
	if err != nil {
		return err
	}

	return nil
}

// UpdateImageRegistryConfig updates the existing image registry with the given name by setting its config.
func UpdateImageRegistryConfig(ctx context.Context, tx *sql.Tx, name string, config map[string]string) error {
	id, err := GetImageRegistryID(ctx, tx, name)
	if err != nil {
		return err
	}

	// Clear the config.
	err = imageRegistryConfigDelete(ctx, tx, id)
	if err != nil {
		return err
	}

	// Apply the new config.
	err = imageRegistryConfigAdd(ctx, tx, id, config)
	if err != nil {
		return err
	}

	return nil
}

// imageRegistryConfigAdd adds config to the image registry with the given ID.
func imageRegistryConfigAdd(ctx context.Context, tx *sql.Tx, registryID int64, config map[string]string) error {
	stmt, err := tx.Prepare("INSERT INTO image_registries_config (image_registry_id, key, value) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}

	defer func() { _ = stmt.Close() }()

	for k, v := range config {
		if v == "" {
			continue
		}

		_, err = stmt.ExecContext(ctx, registryID, k, v)
		if err != nil {
			return err
		}
	}

	return nil
}

// imageRegistryConfigDelete removes all config from the image registry with the given ID.
func imageRegistryConfigDelete(ctx context.Context, tx *sql.Tx, registryID int64) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM image_registries_config WHERE image_registry_id = ?", registryID)
	if err != nil {
		return err
	}

	return nil
}

// imageRegistryConfigGet is a helper to return associated config of the existing image registry with the given ID.
func imageRegistryConfigGet(ctx context.Context, tx *sql.Tx, registryID int64) (map[string]string, error) {
	stmt := `SELECT key, value FROM image_registries_config WHERE image_registry_id = ?`

	config := map[string]string{}
	err := query.Scan(ctx, tx, stmt, func(scan func(dest ...any) error) error {
		var key, value string

		err := scan(&key, &value)
		if err != nil {
			return err
		}

		_, alreadySet := config[key]
		if alreadySet {
			return fmt.Errorf("Duplicate config row found for key %q for image registry ID %d", key, registryID)
		}

		config[key] = value
		return nil
	}, registryID)
	if err != nil {
		return nil, err
	}

	return config, nil
}
