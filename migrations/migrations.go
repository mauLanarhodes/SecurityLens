// Package migrations embeds the SQL schema files so binaries can apply them
// at boot without needing the source tree on disk.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
