# Go Project Rules

Extends my global rules. Go idioms (errors, concurrency, interfaces, testing methodology) are handled by the installed samber/cc-skills-golang skills. Do not restate them here. gofmt and golangci-lint own formatting, imports, and mechanical naming.

## Commands
- Build: [go build ./...]
- Test: [go test -race ./...]
- Lint: [golangci-lint run]
- Vet: [go vet ./...]

## Tests
- Do not create or modify _test.go files unless I explicitly ask.
- When I do ask for tests, follow the skill's testing methodology.
- Never add a test as a side effect of another task.

## Verification gate
- Before claiming done: build passes, go vet clean, golangci-lint clean, and existing tests pass with -race.
- Report the actual command output, not an assumption.
- If no tests exist for the changed code, say so plainly. Do not write them to close the gap unless asked.

## Repo specifics
- [module path, e.g. github.com/you/project]
- [framework if any: gin, echo, chi, or stdlib net/http]
- [anything Claude keeps getting wrong about this repo]