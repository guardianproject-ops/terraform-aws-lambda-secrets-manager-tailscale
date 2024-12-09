{
  system ? "x86_64-linux",
  pkgs ? import <nixpkgs> { inherit system; },
}:

let
  packages = [
    (pkgs.python312.withPackages (
      ps: with ps; [
        pytest
        pytest-mock
        black
        isort
        boto3
        requests
        packaging
      ]
    ))
    pkgs.poetry
    pkgs.zsh
  ];

  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
    pkgs.stdenv.cc.cc
  ];

  # Put the venv on the repo, so direnv can access it
  POETRY_VIRTUALENVS_IN_PROJECT = "true";
  POETRY_VIRTUALENVS_PATH = "{project-dir}/.venv";

  # Use python from path, so you can use a different version to the one bundled with poetry
  POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON = "true";
in
pkgs.mkShell {
  buildInputs = packages;
  shellHook = ''
    export SHELL=${pkgs.zsh}
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}"
    export POETRY_VIRTUALENVS_IN_PROJECT="${POETRY_VIRTUALENVS_IN_PROJECT}"
    export POETRY_VIRTUALENVS_PATH="${POETRY_VIRTUALENVS_PATH}"
    export POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON="${POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON}"
    export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
  '';
}
