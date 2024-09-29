PYTHON=.venv/bin/python
APP=scan_compute.main:app
UVICORN_OPTIONS=--port 8080
CONSUMER=scan_compute.consumer
DS_POLLER=scan_compute.ds_poller
CACHE=scan_compute.populate_cache
NUM_CONSUMERS=3
path := .

define Comment
	- Run `make help` to see all the available options.
	- Run `make lint` to run the linter.
	- Run `make lint-check` to check linter conformity.
	- Run `make run-http` to start the FastAPI app.
	- Run `make run-consumers` to start the Redis consumer.
	- Run `make run-ds-poller` to start the data security poller.
	- Run `make test` to run the tests.
endef

.PHONY: lint
lint: ruff ## Apply ruff linter.

.PHONY: lint-check
lint-check: ## Check whether the codebase satisfies the linter rules.
	@echo
	@echo "Checking linter rules..."
	@echo "========================"
	@echo
	@ruff check $(path)

.PHONY: ruff
ruff: ## Apply ruff.
	@echo "Applying ruff..."
	@echo "================"
	@echo
	@ruff check --fix ./scan_compute

.PHONY: help
help: ## Show this help message.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run the tests.
	@pytest -v

.PHONY: run-http
run-http: ## Run the FastAPI app
	$(PYTHON) -m uvicorn $(APP) $(UVICORN_OPTIONS)

.PHONY: run-consumers
run-consumers: ## Run the consumers
	$(PYTHON) -m $(CONSUMER) --consumers $(NUM_CONSUMERS)

.PHONY: run-ds-poller
run-ds-poller: ## Run the data security poller
	${PYTHON} -m ${DS_POLLER}

.PHONY: cache 
cache: ## populate the cache
	$(PYTHON) -m $(CACHE)
