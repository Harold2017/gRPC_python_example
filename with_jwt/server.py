import grpc
from grpc_reflection.v1alpha import reflection

from with_jwt import Authentication_pb2, Authentication_pb2_grpc

import time
from concurrent import futures

from with_jwt.model import User, JWT_SECRET

from with_jwt.session import QuerySession

import jwt


def get_user_info_by_token(token, jwt_secret):
    print(jwt.decode(token, jwt_secret, algorithms=['HS256']))
    return jwt.decode(token, jwt_secret, algorithms=['HS256'])


class AuthenticationServicer(Authentication_pb2_grpc.AuthenticationServicer):

    def Signup(self, request, context):
        start = time.time()

        res, success = User.create(request.email, request.username, request.password)
        if success:
            print('successfully processed')
            return Authentication_pb2.Response(token=res, time=time.time() - start, status=200)
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details(res)
        return Authentication_pb2.Response(time=time.time() - start, status=500)

    def Login(self, request, context):
        start = time.time()
        res = User.login(request.username, request.password)
        if res:
            print('successfully processed')
            return Authentication_pb2.Response(token=res, time=time.time() - start, status=200)
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details('Invalid username or password')
        return Authentication_pb2.Response(time=time.time() - start, status=500)

    @QuerySession(response_class=Authentication_pb2.QueryResponse, jwt_secret=JWT_SECRET)
    def Query(self, request, context):
        start = time.time()
        meta = dict(context.invocation_metadata())
        print(meta)
        return Authentication_pb2.QueryResponse(res='You are identified as: {}\nYou want to access to API: {}'
                                                .format(get_user_info_by_token(meta.get('session_token'), JWT_SECRET)
                                                        .get('user_info').get('username'), request.api),
                                                time=time.time() - start,
                                                status=200)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    Authentication_pb2_grpc.add_AuthenticationServicer_to_server(AuthenticationServicer(), server)
    SERVICE_NAMES = (
        Authentication_pb2.DESCRIPTOR.services_by_name['Authentication'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
    server.add_insecure_port('[::]:%s' % 20000)
    server.start()
    print('server start...\nlistening on port: %s' % 20000)
    try:
        while True:
            time.sleep(60 * 60 * 24)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    serve()
