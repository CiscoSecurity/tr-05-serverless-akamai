from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
STATE_CONFLICT = 'state conflict'
UNAUTHORIZED = 'unauthorized'
NOT_FOUND = 'not found'
UNAVAILABLE = 'unavailable'


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


class InvalidJWTError(TRFormattedError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'Invalid Authorization Bearer JWT.'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            INVALID_ARGUMENT,
            str(error)
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
