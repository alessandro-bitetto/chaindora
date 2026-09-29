package cli

import "testing"

func TestClassifyGateArgs(t *testing.T) {
	cases := []struct {
		name string
		pm   string
		args []string
		want gateDecision
	}{
		// npm install
		{"npm install lodash", "npm", []string{"install", "lodash"}, gateProceed},
		{"npm i lodash", "npm", []string{"i", "lodash"}, gateProceed},
		{"npm add lodash", "npm", []string{"add", "lodash"}, gateProceed},
		{"npm install (lockfile restore)", "npm", []string{"install"}, gatePassthrough},
		{"npm install with flag only", "npm", []string{"install", "--save-dev"}, gateProceed}, // flags-only filtered later in dispatcher
		{"npm test (not gated)", "npm", []string{"test"}, gatePassthrough},
		{"npm run build (not gated)", "npm", []string{"run", "build"}, gatePassthrough},

		// npm update
		{"npm update lodash", "npm", []string{"update", "lodash"}, gateProceed},
		{"npm up lodash", "npm", []string{"up", "lodash"}, gateProceed},
		{"npm upgrade lodash", "npm", []string{"upgrade", "lodash"}, gateProceed},
		{"npm update (bare — refused)", "npm", []string{"update"}, gateRefuseUpdateAll},
		{"npm up (bare — refused)", "npm", []string{"up"}, gateRefuseUpdateAll},

		// yarn add / upgrade
		{"yarn add lodash", "yarn", []string{"add", "lodash"}, gateProceed},
		{"yarn install (lockfile)", "yarn", []string{"install"}, gatePassthrough},
		{"yarn upgrade lodash", "yarn", []string{"upgrade", "lodash"}, gateProceed},
		{"yarn upgrade-interactive lodash", "yarn", []string{"upgrade-interactive", "lodash"}, gateProceed},
		{"yarn up lodash", "yarn", []string{"up", "lodash"}, gateProceed},
		{"yarn upgrade (bare — refused)", "yarn", []string{"upgrade"}, gateRefuseUpdateAll},

		// pnpm add / update
		{"pnpm add lodash", "pnpm", []string{"add", "lodash"}, gateProceed},
		{"pnpm install (lockfile)", "pnpm", []string{"install"}, gatePassthrough},
		{"pnpm update lodash", "pnpm", []string{"update", "lodash"}, gateProceed},
		{"pnpm up lodash", "pnpm", []string{"up", "lodash"}, gateProceed},
		{"pnpm upgrade lodash", "pnpm", []string{"upgrade", "lodash"}, gateProceed},
		{"pnpm update (bare — refused)", "pnpm", []string{"update"}, gateRefuseUpdateAll},

		// pip — upgrade is a flag on install, no separate verb needed.
		{"pip install requests", "pip", []string{"install", "requests"}, gateProceed},
		{"pip install --upgrade requests", "pip", []string{"install", "--upgrade", "requests"}, gateProceed},
		{"pip install (alone)", "pip", []string{"install"}, gatePassthrough},
		{"pip3 install requests", "pip3", []string{"install", "requests"}, gateProceed},

		// cargo
		{"cargo add serde", "cargo", []string{"add", "serde"}, gateProceed},
		{"cargo install ripgrep", "cargo", []string{"install", "ripgrep"}, gateProceed},
		{"cargo update serde", "cargo", []string{"update", "serde"}, gateProceed},
		{"cargo update (bare — refused)", "cargo", []string{"update"}, gateRefuseUpdateAll},
		{"cargo build (not gated)", "cargo", []string{"build"}, gatePassthrough},

		// go — get -u uses existing get verb
		{"go get cobra", "go", []string{"get", "github.com/spf13/cobra"}, gateProceed},
		{"go get -u cobra", "go", []string{"get", "-u", "github.com/spf13/cobra"}, gateProceed},
		{"go install cobra", "go", []string{"install", "github.com/spf13/cobra@latest"}, gateProceed},
		{"go run (not gated)", "go", []string{"run", "./..."}, gatePassthrough},

		// empty / unknown
		{"empty args", "npm", []string{}, gatePassthrough},

		// === characterization-test sweep: every PM the
		// gate supports must have at least one positive (proceed)
		// and one negative (passthrough) case here. Added before
		// the classifyGateArgs verb-table refactor so the refactor
		// is provably behavior-preserving. ===

		// dotnet — multi-token verb: `dotnet add package <id>`
		{"dotnet add package", "dotnet", []string{"add", "package", "Newtonsoft.Json"}, gateProceed},
		{"dotnet add reference (not gated)", "dotnet", []string{"add", "reference", "Foo.csproj"}, gatePassthrough},
		{"dotnet build (not gated)", "dotnet", []string{"build"}, gatePassthrough},

		// poetry
		{"poetry add requests", "poetry", []string{"add", "requests"}, gateProceed},
		{"poetry install (lockfile)", "poetry", []string{"install"}, gatePassthrough},
		{"poetry update requests", "poetry", []string{"update", "requests"}, gateProceed},
		{"poetry update (bare — refused)", "poetry", []string{"update"}, gateRefuseUpdateAll},

		// uv — current code only recognizes `uv add` and `uv lock`.
		// `uv pip install ...` (the pip-compat interface) is not gated.
		// Likely a coverage gap; pinning current behavior for the refactor.
		{"uv add requests", "uv", []string{"add", "requests"}, gateProceed},
		{"uv lock (bare — refused)", "uv", []string{"lock"}, gateRefuseUpdateAll},
		{"uv pip install (gap: not gated)", "uv", []string{"pip", "install", "requests"}, gatePassthrough},

		// bun
		{"bun add lodash", "bun", []string{"add", "lodash"}, gateProceed},
		{"bun install lodash", "bun", []string{"install", "lodash"}, gateProceed},
		{"bun i lodash", "bun", []string{"i", "lodash"}, gateProceed},
		{"bun install (lockfile)", "bun", []string{"install"}, gatePassthrough},
		{"bun run (not gated)", "bun", []string{"run", "dev"}, gatePassthrough},

		// pipenv
		{"pipenv install requests", "pipenv", []string{"install", "requests"}, gateProceed},
		{"pipenv shell (not gated)", "pipenv", []string{"shell"}, gatePassthrough},

		// pdm
		{"pdm add requests", "pdm", []string{"add", "requests"}, gateProceed},
		{"pdm install (not an add verb)", "pdm", []string{"install"}, gatePassthrough},

		// deno — cwd-only
		{"deno cache main.ts (cwd-only)", "deno", []string{"cache", "main.ts"}, gateProceed},
		{"deno add npm:lodash (cwd-only)", "deno", []string{"add", "npm:lodash"}, gateProceed},
		{"deno install (cwd-only)", "deno", []string{"install"}, gateProceed},
		{"deno run (not gated)", "deno", []string{"run", "main.ts"}, gatePassthrough},

		// paket — cwd-only
		{"paket install (cwd-only)", "paket", []string{"install"}, gateProceed},
		{"paket restore (cwd-only)", "paket", []string{"restore"}, gateProceed},
		{"paket simplify (not gated)", "paket", []string{"simplify"}, gatePassthrough},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGateArgs(tc.pm, tc.args)
			if got != tc.want {
				t.Errorf("classifyGateArgs(%q, %v) = %d, want %d", tc.pm, tc.args, got, tc.want)
			}
		})
	}
}
