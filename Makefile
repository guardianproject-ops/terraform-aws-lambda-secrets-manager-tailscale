SHELL := /bin/bash

export TERRAFORM_VERSION := 1.5.7
export README_DEPS ?=  docs/terraform.md
export HELP_FILTER ?= readme

-include $(shell curl -sSL -o .build-harness-ext "https://go.sr2.uk/build-harness"; echo .build-harness-ext)

export README_TEMPLATE_FILE := ${BUILD_HARNESS_EXTENSIONS_PATH}/templates/README_gp.md.gotmpl


## Lint terraform code
lint:
	$(SELF) readme/lint terraform/install terraform/get-modules terraform/lint terraform/validate tflint

