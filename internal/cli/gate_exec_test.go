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

		// npm update — NEW in v0.13.4
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

		// bundle / gem
		{"bundle add rspec", "bundle", []string{"add", "rspec"}, gateProceed},
		{"bundle install (lockfile)", "bundle", []string{"install"}, gatePassthrough},
		{"bundle update rspec", "bundle", []string{"update", "rspec"}, gateProceed},
		{"bundle update (bare — refused)", "bundle", []string{"update"}, gateRefuseUpdateAll},
		{"gem install rails", "gem", []string{"install", "rails"}, gateProceed},
		{"gem update rails", "gem", []string{"update", "rails"}, gateProceed},
		{"gem update (bare — refused)", "gem", []string{"update"}, gateRefuseUpdateAll},

		// mvn — no upgrade verb (version bumps via pom.xml edits)
		{"mvn dependency:get", "mvn", []string{"dependency:get", "-Dartifact=g:a:v"}, gateProceed},
		{"mvn compile (not gated)", "mvn", []string{"compile"}, gatePassthrough},

		// go — get -u uses existing get verb
		{"go get cobra", "go", []string{"get", "github.com/spf13/cobra"}, gateProceed},
		{"go get -u cobra", "go", []string{"get", "-u", "github.com/spf13/cobra"}, gateProceed},
		{"go install cobra", "go", []string{"install", "github.com/spf13/cobra@latest"}, gateProceed},
		{"go run (not gated)", "go", []string{"run", "./..."}, gatePassthrough},

		// empty / unknown
		{"empty args", "npm", []string{}, gatePassthrough},
		{"unknown pm", "ninja", []string{"build"}, gatePassthrough},

		// === v0.17 characterization-test sweep: every PM the
		// gate supports must have at least one positive (proceed)
		// and one negative (passthrough) case here. Added before
		// the classifyGateArgs verb-table refactor so the refactor
		// is provably behavior-preserving. ===

		// dotnet — multi-token verb: `dotnet add package <id>`
		{"dotnet add package", "dotnet", []string{"add", "package", "Newtonsoft.Json"}, gateProceed},
		{"dotnet add reference (not gated)", "dotnet", []string{"add", "reference", "Foo.csproj"}, gatePassthrough},
		{"dotnet build (not gated)", "dotnet", []string{"build"}, gatePassthrough},

		// composer
		{"composer require monolog", "composer", []string{"require", "monolog/monolog"}, gateProceed},
		{"composer install (lockfile)", "composer", []string{"install"}, gatePassthrough},
		{"composer update monolog", "composer", []string{"update", "monolog/monolog"}, gateProceed},
		{"composer update (bare — refused)", "composer", []string{"update"}, gateRefuseUpdateAll},

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

		// gradle — cwd-only; resolving tasks gate even with no positional pkgs
		{"gradle build (cwd-only)", "gradle", []string{"build"}, gateProceed},
		{"gradle dependencies (cwd-only)", "gradle", []string{"dependencies"}, gateProceed},
		{"gradle clean (not gated)", "gradle", []string{"clean"}, gatePassthrough},

		// pod (CocoaPods) — cwd-only
		{"pod install (cwd-only)", "pod", []string{"install"}, gateProceed},
		{"pod update (cwd-only)", "pod", []string{"update"}, gateProceed},
		{"pod init (not gated)", "pod", []string{"init"}, gatePassthrough},

		// swift — multi-token: `swift package resolve` / `swift package update`
		{"swift package resolve", "swift", []string{"package", "resolve"}, gateProceed},
		{"swift package update", "swift", []string{"package", "update"}, gateProceed},
		{"swift build (not gated)", "swift", []string{"build"}, gatePassthrough},
		{"swift package init (not gated)", "swift", []string{"package", "init"}, gatePassthrough},

		// dart / flutter — `<pm> pub add` etc.
		{"dart pub add http", "dart", []string{"pub", "add", "http"}, gateProceed},
		{"dart pub get", "dart", []string{"pub", "get"}, gateProceed},
		{"dart pub upgrade", "dart", []string{"pub", "upgrade"}, gateProceed},
		{"flutter pub add http", "flutter", []string{"pub", "add", "http"}, gateProceed},
		{"dart run (not gated)", "dart", []string{"run"}, gatePassthrough},

		// mix (Hex / Elixir) — only deps.* verbs are gated; mix compile
		// itself doesn't pull from hex.pm (it compiles already-fetched deps).
		{"mix deps.get (cwd-only)", "mix", []string{"deps.get"}, gateProceed},
		{"mix deps.update (cwd-only)", "mix", []string{"deps.update"}, gateProceed},
		{"mix compile (not a deps verb)", "mix", []string{"compile"}, gatePassthrough},
		{"mix test (not gated)", "mix", []string{"test"}, gatePassthrough},

		// bun
		{"bun add lodash", "bun", []string{"add", "lodash"}, gateProceed},
		{"bun install lodash", "bun", []string{"install", "lodash"}, gateProceed},
		{"bun i lodash", "bun", []string{"i", "lodash"}, gateProceed},
		{"bun install (lockfile)", "bun", []string{"install"}, gatePassthrough},
		{"bun run (not gated)", "bun", []string{"run", "dev"}, gatePassthrough},

		// conda / mamba / micromamba
		{"conda install numpy", "conda", []string{"install", "numpy"}, gateProceed},
		{"conda update numpy", "conda", []string{"update", "numpy"}, gateProceed},
		{"mamba install numpy", "mamba", []string{"install", "numpy"}, gateProceed},
		{"micromamba install numpy", "micromamba", []string{"install", "numpy"}, gateProceed},
		{"conda list (not gated)", "conda", []string{"list"}, gatePassthrough},

		// brew
		{"brew install jq", "brew", []string{"install", "jq"}, gateProceed},
		{"brew upgrade jq", "brew", []string{"upgrade", "jq"}, gateProceed},
		{"brew reinstall jq", "brew", []string{"reinstall", "jq"}, gateProceed},
		{"brew list (not gated)", "brew", []string{"list"}, gatePassthrough},

		// conan
		{"conan install .", "conan", []string{"install", "."}, gateProceed},
		{"conan create (not gated)", "conan", []string{"create", "."}, gatePassthrough},

		// vcpkg
		{"vcpkg install fmt", "vcpkg", []string{"install", "fmt"}, gateProceed},
		{"vcpkg list (not gated)", "vcpkg", []string{"list"}, gatePassthrough},

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

		// stack — cwd-only
		{"stack build (cwd-only)", "stack", []string{"build"}, gateProceed},
		{"stack test (cwd-only)", "stack", []string{"test"}, gateProceed},
		{"stack new (not gated)", "stack", []string{"new", "project"}, gatePassthrough},

		// cabal — cwd-only
		{"cabal build (cwd-only)", "cabal", []string{"build"}, gateProceed},
		{"cabal install pkg (cwd-only)", "cabal", []string{"install", "lens"}, gateProceed},
		{"cabal init (not gated)", "cabal", []string{"init"}, gatePassthrough},

		// sbt — cwd-only
		{"sbt compile (cwd-only)", "sbt", []string{"compile"}, gateProceed},
		{"sbt test (cwd-only)", "sbt", []string{"test"}, gateProceed},
		{"sbt clean (not gated)", "sbt", []string{"clean"}, gatePassthrough},

		// opam
		{"opam install dune", "opam", []string{"install", "dune"}, gateProceed},
		{"opam list (not gated)", "opam", []string{"list"}, gatePassthrough},

		// rebar3 — cwd-only
		{"rebar3 compile (cwd-only)", "rebar3", []string{"compile"}, gateProceed},
		{"rebar3 deps (cwd-only)", "rebar3", []string{"deps"}, gateProceed},
		{"rebar3 shell (not gated)", "rebar3", []string{"shell"}, gatePassthrough},

		// paket — cwd-only
		{"paket install (cwd-only)", "paket", []string{"install"}, gateProceed},
		{"paket restore (cwd-only)", "paket", []string{"restore"}, gateProceed},
		{"paket simplify (not gated)", "paket", []string{"simplify"}, gatePassthrough},

		// cpanm — any non-flag arg is install
		// KNOWN BUG: `cpanm Module::Name` currently falls through to
		// the bare-verb passthrough branch (len(args)==1 && isInstall
		// && !cwdOnly) which was designed for `npm install` alone =
		// lockfile restore. cpanm has no verb syntax, so its only-arg
		// IS the package, not a "lockfile restore" signal. This test
		// pins the (buggy) current behavior so the v0.17 verb-table
		// refactor doesn't accidentally fix or worsen it. Follow-up
		// fix: mark cpanm as "no-verb PM" in the handler table and
		// skip the bare-args passthrough check for it.
		{"cpanm Module::Name (BUG: not gated)", "cpanm", []string{"Module::Name"}, gatePassthrough},
		{"cpanm with flag only", "cpanm", []string{"--help"}, gatePassthrough},
		{"cpanm two args (correctly gated)", "cpanm", []string{"Module::Name", "Other::Module"}, gateProceed},

		// luarocks
		{"luarocks install lpeg", "luarocks", []string{"install", "lpeg"}, gateProceed},
		{"luarocks list (not gated)", "luarocks", []string{"list"}, gatePassthrough},

		// carthage — cwd-only
		{"carthage update (cwd-only)", "carthage", []string{"update"}, gateProceed},
		{"carthage bootstrap (cwd-only)", "carthage", []string{"bootstrap"}, gateProceed},
		{"carthage archive (not gated)", "carthage", []string{"archive"}, gatePassthrough},

		// elm
		{"elm install elm/json", "elm", []string{"install", "elm/json"}, gateProceed},
		{"elm make (not gated)", "elm", []string{"make"}, gatePassthrough},

		// nimble
		{"nimble install zip", "nimble", []string{"install", "zip"}, gateProceed},
		// `nimble develop` alone (no package arg) currently falls into the
		// bare-verb passthrough branch. nimble develop actually does pull
		// deps for the cwd project, so the behavior is debatable; pinning
		// current behavior to keep the refactor neutral. Same passthrough
		// reasoning as `npm install` alone (lockfile restore).
		{"nimble develop (bare verb, passthrough)", "nimble", []string{"develop"}, gatePassthrough},
		{"nimble develop pkg", "nimble", []string{"develop", "mylib"}, gateProceed},
		{"nimble test (not gated)", "nimble", []string{"test"}, gatePassthrough},

		// shards — cwd-only
		{"shards install (cwd-only)", "shards", []string{"install"}, gateProceed},
		{"shards update (cwd-only)", "shards", []string{"update"}, gateProceed},
		{"shards init (not gated)", "shards", []string{"init"}, gatePassthrough},

		// zig — cwd-only
		{"zig build (cwd-only)", "zig", []string{"build"}, gateProceed},
		{"zig test (cwd-only)", "zig", []string{"test", "src/main.zig"}, gateProceed},
		{"zig fmt (not gated)", "zig", []string{"fmt", "."}, gatePassthrough},

		// julia / R / Rscript — always (cwd-only resolver decides)
		{"julia run", "julia", []string{"--project=."}, gateProceed},
		{"R cli", "R", []string{"--no-save"}, gateProceed},
		{"Rscript run", "Rscript", []string{"script.R"}, gateProceed},
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
