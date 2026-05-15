package heuristic

// Curated lists of high-target packages per ecosystem. These are intentionally
// kept small (~50 each) to focus on the names most likely to be typosquatted
// or maintainer-compromised. The lists are stable enough at the top of the
// curve that hardcoded slices don't go stale quickly. Contributions welcome
// via the incident-pack PR flow (see CONTRIBUTING.md).
//
// Names follow each ecosystem's normalization rules:
//   - npm: literal package name, lowercase (scoped packages excluded; they
//     have their own dep-confusion detector)
//   - PyPI: PEP 503 normalized (lowercase, [-_.] runs collapsed to "-")

var topNPM = []string{
	"lodash", "react", "react-dom", "axios", "express", "moment", "debug",
	"chalk", "commander", "ms", "minimist", "request", "uuid", "semver",
	"mkdirp", "rimraf", "glob", "tslib", "typescript", "webpack", "jquery",
	"vue", "next", "redux", "react-router-dom", "fs-extra", "yargs", "dotenv",
	"eslint", "jest", "mocha", "prettier", "underscore", "async", "ws",
	"socket.io", "passport", "bcrypt", "jsonwebtoken", "mongoose", "body-parser",
	"cors", "helmet", "morgan", "pug", "ejs", "cheerio", "puppeteer", "babel",
	"node-fetch", "got",
}

var topPyPI = []string{
	"requests", "urllib3", "six", "certifi", "idna", "charset-normalizer",
	"setuptools", "pip", "boto3", "botocore", "numpy", "pandas", "scipy",
	"matplotlib", "django", "flask", "sqlalchemy", "pytest", "pyyaml", "click",
	"jinja2", "markupsafe", "werkzeug", "cryptography", "pytz", "python-dateutil",
	"attrs", "awscli", "beautifulsoup4", "lxml", "packaging", "pillow",
	"psycopg2", "redis", "scikit-learn", "selenium", "tornado", "fastapi",
	"gunicorn", "pydantic", "pymongo", "pyparsing", "tqdm", "virtualenv",
	"wheel", "aiohttp", "celery", "openssl", "mypy", "black",
}

func isInList(name string, list []string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

// levenshtein computes the edit distance between two strings using a single
// rolling row of size len(b)+1.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	ar := []rune(a)
	br := []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
