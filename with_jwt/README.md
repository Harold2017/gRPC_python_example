#
### gRPC python example with jwt
```bash
.
├── Authentication_pb2_grpc.py
├── Authentication_pb2.py
├── Authentication.proto        # proto file
├── __init__.py
├── keys                        # jwt secret
│   ├── server.crt
│   └── server.key
├── model                       # simple db model
│   ├── db_session.py
│   ├── __init__.py
│   └── User.py
├── Makefile                    # cmd
├── server.py
├── client.py
└── session.py                  # gRPC session with token validation
```

simple demo of gRPC with token in metadata