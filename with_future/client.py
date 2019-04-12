from __future__ import print_function
import logging

import grpc

import greeting_pb2
import greeting_pb2_grpc


def run():

    def process_response(response):
        print(response.result())

    channel = grpc.insecure_channel('localhost:10000')
    stub = greeting_pb2_grpc.GreetingStub(channel)
    response = stub.Hello.future(greeting_pb2.HelloRequest(name='Sophia'))
    response.add_done_callback(process_response)
    print('Sophia, i like you!')
    print("Greeter client received: " + response.result().greetings)


if __name__ == '__main__':
    logging.basicConfig()
    run()
