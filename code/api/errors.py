from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
STATE_CONFLICT = 'state conflict'
UNAUTHORIZED = 'unauthorized'
NOT_FOUND = 'not found'
UNAVAILABLE = 'unavailable'
AUTH_ERROR = 'authorization error'
CONNECTION_ERROR = 'connection error'
HEALTH_CHECK_ERROR = 'health check failed'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            INVALID_ARGUMENT,
            str(error)
        )


class AkamaiSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class AkamaiConnectionError(TRFormattedError):
    def __init__(self, url):
        super().__init__(
            CONNECTION_ERROR,
            f'Unable to connect Akamai, validate the configured baseUrl: {url}'
        )


class CriticalAkamaiResponseError(TRFormattedError):
    def __init__(self, response):
        """
        https://developer.akamai.com/api/cloud_security/network_lists/v2.html#getlists
        """
        status_code_map = {
            HTTPStatus.BAD_REQUEST: INVALID_ARGUMENT,
            HTTPStatus.UNAUTHORIZED: UNAUTHORIZED,
            HTTPStatus.FORBIDDEN: PERMISSION_DENIED,
            HTTPStatus.NOT_FOUND: NOT_FOUND,
            HTTPStatus.CONFLICT: STATE_CONFLICT,
            HTTPStatus.UNPROCESSABLE_ENTITY: INVALID_ARGUMENT,
            HTTPStatus.INTERNAL_SERVER_ERROR: UNKNOWN,

        }

        super().__init__(
            status_code_map.get(response.status_code),
            'Unexpected response from Akamai:'
            f' {response.json().get("detail") or response.text}'
        )


class AkamaiWatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            HEALTH_CHECK_ERROR,
            'Invalid Health Check'
        )
