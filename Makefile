SHELL := /bin/bash

export HELP_FILTER ?= help|terraform|lint

ifneq ("$(wildcard context.tf)", "")
  export README_DEPS ?= docs/targets.md docs/terraform-split.md
else
  export README_DEPS ?= docs/targets.md docs/terraform.md
endif

ifneq ($(shell test -e versions.tf && grep -q 'configuration_aliases' versions.tf && echo configuration_aliases),)
  # When configuration_aliases are used, validate will always fail as the provider
  # configuration is not present in the module
  export LINT_TF_VALIDATE =
else
  export LINT_TF_VALIDATE = terraform/validate
endif

-include $(shell curl -sSL -o .build-harness-ext "https://go.sr2.uk/build-harness"; echo .build-harness-ext)

export README_TEMPLATE_FILE := ${BUILD_HARNESS_EXTENSIONS_PATH}/templates/README_gp.md.gotmpl

## Lint terraform code
lint:
	$(SELF) readme/lint terraform/install terraform/get-modules terraform/lint $(LINT_TF_VALIDATE) tflint
