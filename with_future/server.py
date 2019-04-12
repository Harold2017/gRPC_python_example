import grpc
import greeting_pb2
import greeting_pb2_grpc

from concurrent import futures
import logging
import time


class Greeter(greeting_pb2_grpc.GreetingServicer):
    def Hello(self, request, context):
        time.sleep(5)
        return greeting_pb2.Response(greetings='Hello, %s!' % request.name)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    greeting_pb2_grpc.add_GreetingServicer_to_server(Greeter(), server)
    server.add_insecure_port('[::]:10000')
    server.start()
    try:
        while True:
            time.sleep(60 * 60 * 24)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    logging.basicConfig()
    serve()
