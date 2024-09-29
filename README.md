# Scan Compute Service

    - Run `make help` to see all the available options.
    - Run `make lint` to run the linter.
    - Run `make lint-check` to check linter conformity.
    - Run `make test` to run the tests.

## To run a scan in Scan Compute to understand the flow:

- Run `make run-http` and `make run-consumers`
- once the API server and the consumers are running, go ahead and run `bash test_curl.sh`

> [!NOTE]
> must have a local redis container running
> add an `.env` file based on the sample env
