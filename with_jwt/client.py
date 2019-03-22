import grpc
from with_jwt import Authentication_pb2, Authentication_pb2_grpc
import os
import sys
import argparse
from grpc_reflection.v1alpha import reflection
import time
import json


########################################################################################################################
# section to handle parsing args

def get_argparser(version: str):
    """
    generate argparser
    :param version: version string
    :return: args dict
    """
    parser = argparse.ArgumentParser(description='test gRPC server with specified json file')
    parser.add_argument('-v', '--version', action='version', help='print version info and exit',
                        version='test_client_tool {}'.format(version))

    parser.add_argument('-c', '--channel', choices=['secure', 'insecure'],
                        help='channel security, default is insecure', required=False)

    parser.add_argument('-a', '--address', help='gRPC server address in form of ip:port',
                        type=str, required=True)

    parser.add_argument('-l', '--list', action='store_true', help='list services on ip:port', required=False)

    parser.add_argument('-rpc', '--rpc_call', help='rpc name you want to call',
                        type=str, choices=['Signup', 'Login', 'Query'], required=False)

    parser.add_argument('-d', '--data', help='data in json format)', type=str, required=False)

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()

    return args


########################################################################################################################


def get_client_credentials():
    # read in certificate
    with open(os.getenv('GRPC_PUBLIC_KEY'), 'rb') as f:
        creds = f.read()

    # create credentials
    credentials = grpc.ssl_channel_credentials(root_certificates=creds)
    return credentials


def run_stub(method, data):
    start = time.time()
    data = json.loads(data)
    stub = Authentication_pb2_grpc.AuthenticationStub(channel)
    response = None

    if method == 'Query':
        response = stub.Query(Authentication_pb2.QueryRequest(api=data['api']),
                              metadata=(('session_token', data['session_token']),))
        print(response.res)
    elif method == 'Signup':
        response = stub.Signup(Authentication_pb2.SignupRequest(**data))
        print('user token: %s' % response.token)
    elif method == 'Login':
        response = stub.Login(Authentication_pb2.LoginRequest(**data))
        print('user token: %s' % response.token)
    else:
        print('Unsupported service')
    end = time.time()
    print("time consumption: ", end - start)
    if response.status == 200:
        print('Successfully processed, server time consumption is: %s' % response.time)


def list_services(address, channel):
    stub = reflection._reflection_pb2_grpc.ServerReflectionStub(channel)

    def gen():
        yield reflection._reflection_pb2.ServerReflectionRequest(host=address, list_services='')

    result = [r for r in stub.ServerReflectionInfo(gen())]
    print("Available services:\n%r" % result[0].list_services_response)


if __name__ == '__main__':
    args = get_argparser(version='0.0.1')
    if args.channel == 'secure':
        channel = grpc.secure_channel(args.address, get_client_credentials())
    else:
        channel = grpc.insecure_channel(args.address)
    if args.list:
        list_services(args.address, channel)
    if args.address and args.rpc_call and args.data:
        run_stub(args.rpc_call, args.data)
