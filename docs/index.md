# Basic Nano Client

[github.com/nanoswap/basicnanoclient](https://github.com/nanoswap/basicnanoclient)

# Installation

```
pip install basicnanoclient
```

# Usage

https://github.com/nanoswap/basicnanoclient/blob/main/notebooks/nano.ipynb

# Running a local Nano Node

```
# https://github.com/nanocurrency/nano-node/releases/
docker pull nanocurrency/nano-test:${NANO_TAG}
docker run --restart=unless-stopped -d -p 127.0.0.1:17076:17076 -v ${NANO_HOST_DIR}:/root --name ${NANO_NAME} nanocurrency/nano-test:${NANO_TAG}
 ```

# See also

[github.com/nanoswap/nanohelp](https://github.com/nanoswap/nanohelp)
