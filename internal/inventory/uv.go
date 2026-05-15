package inventory

// uv.lock is a TOML lockfile produced by the `uv` Python package installer.
// Its [[package]] block structure is identical to poetry.lock's, so we reuse
// the same lightweight TOML scanner.
func parseUVLock(path string) ([]Package, error) {
	return parsePoetryLock(path)
}
