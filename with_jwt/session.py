import jwt
import grpc


class QuerySession:
    def __init__(self, response_class, jwt_secret=None):
        self.response = response_class
        self.jwt_secret = jwt_secret

    def __call__(self, func):  # as wrapper
        def _authenticate(instance, request, context):
            success, error = self.authenticate(context)
            if not success:
                return error
            return func(instance, request, context)
        return _authenticate

    def authenticate(self, context):
        meta = dict(context.invocation_metadata())
        session_token = meta['session_token']
        success, details = self.verify_token(session_token)
        if success:
            return True, None
        return False, self.error_handler(context, details)

    def verify_token(self, session_token):
        try:
            jwt.decode(session_token, key=self.jwt_secret).get('user_info')
        except Exception as e:
            return False, e
        return True, None

    def error_handler(self, context, details):
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details(details)
        return self.response()
