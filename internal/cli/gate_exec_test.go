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
