# IPFS Key Value Store 

[github.com/nanoswap/ipfskvs](https://github.com/nanoswap/ipfskvs)

# Installation

```
pip install ipfskvs
```

# Wrappers for IPFS RPC endpoints
```py
    from ipfskvs.ipfs import Ipfs

    client = ipfs.Ipfs()  # defaults to http://127.0.0.1:5001/api/v0
    client.mkdir("my_dir")
    client.add("my_dir/my_file", b"my_contents")
```

# Read and write protobuf contents

## Reading:
```py
    from ipfskvs.index import Index
    from ipfskvs.ipfs import Ipfs
    from ipfskvs.store import Store
    from myprotobuf_pb2 import MyProtobuf

    store = Store(
        Index.from_filename("myfile.txt"),
        ipfs=Ipfs(host="127.0.0.1", port="5001"),
        reader=MyProtobuf()
    )

    store.read()
    print(store.reader)
```

## Writing:
```py
    from ipfskvs.index import Index
    from ipfskvs.ipfs import Ipfs
    from ipfskvs.store import Store
    from myprotobuf_pb2 import MyProtobuf

    store = Store(
        Index.from_filename("myfile.txt"),
        ipfs=Ipfs(host="127.0.0.1", port="5001"),
        writer=MyProtobuf()
    )
    store.add()
```

# Overhead for nested directories

## Write with multiple indexes
Create a tiered file structure based on IDs, ex:
```bash
    ├── fashion/
        ├── designer_1.manufacturer_1
        ├── designer_2.manufacturer_1
            ├── deal_16.data
        ├── designer_4.manufacturer_3
            ├── deal_1.data
            ├── deal_2.data
```
```py
    from ipfskvs.index import Index
    from ipfskvs.ipfs import Ipfs
    from ipfskvs.store import Store
    from deal_pb2 import Deal

    index = Index(
        prefix="fashion",
        index={
            "designer": str(uuid.uuid4()),
            "manufacturer": str(uuid.uuid4())
        }, subindex=Index(
            index={
                "deal":  str(uuid.uuid4())
            }
        )
    )

    data = Deal(type=Type.BUZZ, content="fizz")
    store = Store(index=index, ipfs=Ipfs(), writer=data)
    store.add()
```

## Query the multiple indexes
Ex: get all deals with designer id "123"
```py
    from ipfskvs.index import Index
    from ipfskvs.ipfs import Ipfs
    from ipfskvs.store import Store
    from deal_pb2 import Deal

    query_index = Index(
        prefix="fashion",
        index={
            "designer": "123"
        }
    )

    reader = Deal()
    query_results = Store.query(query_index, ipfs, reader)
    print(Store.to_dataframe(query_results))
```
