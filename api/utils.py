import json
from typing import Union

from authlib.jose import jwt
from authlib.jose.errors import DecodeError, BadSignatureError
from flask import request, current_app, jsonify, g

from api.errors import InvalidArgumentError, AuthorizationError


def get_auth_token() -> Union[str, Exception]:
    """Parse and validate incoming authorization header"""
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt() -> Union[dict, Exception]:
    """Decode Authorization token and validate credentials."""
    jwt_payload_keys = (
        'baseUrl',
        'accessToken',
        'clientToken',
        'clientSecret'
    )
    expected_errors = {
        AssertionError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    try:
        payload = jwt.decode(
            get_auth_token(), current_app.config['SECRET_KEY']
        )
        assert set(payload) == set(jwt_payload_keys)
        return payload
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(
            f'Invalid JSON payload received. {json.dumps(message)}'
        )

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_result():
    result = {'data': {}}

    if g.get('status'):
        result['data']['status'] = g.status

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def add_status(status):
    g.status = status


def add_error(error):
    g.errors = [*g.get('errors', []), error.json]
