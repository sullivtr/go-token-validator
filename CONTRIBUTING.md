# Contributing

By participating to this project, you agree to abide our [code of
conduct](/CODE_OF_CONDUCT.md).

## Setup your machine

`go-token-validator` is written in [Go](https://golang.org/).

Prerequisites:

- [Go 1.15+](https://golang.org/doc/install)

## Test your change

- run `go test ./... -coverprofile=cover.out` from the root of this repository.
- ensure your changes are covered by running `go tool cover -html=cover.out`


## Create a commit

Commit messages should be well formatted, and to make that "standardized", we
are using Conventional Commits.

You can follow the documentation on
[their website](https://www.conventionalcommits.org).

## Submit a pull request

Push your branch to your `go-token-validator` fork and open a pull request against the
master branch.



