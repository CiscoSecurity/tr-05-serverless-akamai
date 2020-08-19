import json

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g

from api.errors import InvalidJWTError, InvalidArgumentError


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    """

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        raise InvalidJWTError


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

    if g.status:
        result['data']['status'] = g.status

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def add_status(status):
    g.status = status


def add_error(error):
    g.errors = [*g.get('errors', []), error.json]
