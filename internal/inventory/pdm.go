package inventory

// parsePDMLock parses pdm.lock — TOML with [[package]] blocks
// shaped identically to poetry.lock. Reuse the Poetry parser.
func parsePDMLock(path string) ([]Package, error) {
	return parsePoetryLock(path)
}
