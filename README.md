# basicnanoclient

A nano (XNO) cryptocurrency RPC python client and client side wallet

![](https://img.shields.io/readthedocs/nanoclient?label=readthedocs)
![](https://img.shields.io/github/actions/workflow/status/nanoswap/nanoclient/test.yml?label=tests)
![](https://img.shields.io/snyk/vulnerabilities/github/nanoswap/nanoclient)
![](https://img.shields.io/pypi/pyversions/nanoclient)

- [Installation](#installation)
- [Documentation](#documentation)
  * [Build docs locally](#build-docs-locally)
- [Tests](#tests)
  * [Before running tests:](#before-running-tests-)

## Installation

```
pip install basicnanoclient
```

## Documentation

https://basicnanoclient.readthedocs.io/

### Build docs locally
`mkdocs serve`

## Tests
To only run tests: `pytest --cov=basicnanoclient --cov-fail-under=80`

To run style checks:  
```
flake8 basicnanoclient --docstring-convention google --ignore=D100
flake8 tests --docstring-convention google --ignore=D100
```

To run all checks: `nox`

### Before running tests:

- install a local nano test node
- run it locally

## Running a local Nano Node

```
# https://github.com/nanocurrency/nano-node/releases/
docker pull nanocurrency/nano-test:${NANO_TAG}
docker run --restart=unless-stopped -d -p 127.0.0.1:17076:17076 -v ${NANO_HOST_DIR}:/root --name ${NANO_NAME} nanocurrency/nano-test:${NANO_TAG}
```
