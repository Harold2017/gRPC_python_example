stubs:
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. Authentication.proto

db:
	docker run --name mariadb -p 3306:3306 -e MYSQL_ROOT_PASSWORD=123456 -d mariadb:latest

server:
	python server.py

client:
	python client.py -a localhost:20000 -l

signup:
	python client.py -a localhost:20000 -rpc Login -d '{"email": "test@test.com", "username": "test_test", "password": "test"}'

login:
	python client.py -a localhost:20000 -rpc Login -d '{"username": "test_test", "password": "test"}'

query:
	python client.py -a localhost:20000 -rpc Query -d \
	'{"session_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2luZm8iOnsidXNlcl9pZCI6NCwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwidXNlcm5hbWUiOiJ0ZXN0X3Rlc3QiLCJpc19hZG1pbiI6ZmFsc2V9LCJleHAiOjE1NTUzMTc0NzZ9.jfrLXLuNZ40uETG3SZnnrBxlxcRuoG3zteMeHFO3Z7A", "api": "/test"}'

gen_key:
	openssl req -newkey rsa:2048 -nodes -subj '/O=ASTRI/C=CN/OU=MSA/CN=localhost' \
	-keyout keys/server.key -x509 -days 365 -out keys/server.crt

grpcurl_list:
	grpcurl -insecure localhost:20000 list