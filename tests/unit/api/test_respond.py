from http import HTTPStatus

from pytest import fixture

from api.errors import INVALID_ARGUMENT
from .utils import headers


def routes():
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_respond_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@fixture(scope='module')
def invalid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'domain'}]

    if route.endswith('/trigger'):
        return {'observable_type': 'domain',
                'observable_value': 'cisco.com'}


@fixture(scope='module')
def invalid_json_expected_payload(route):
    message = None
    if route.endswith('/observables'):
        message = '{"0": {"value": ["Missing data for required field."]}}'
    if route.endswith('/trigger'):
        message = '{"action-id": ["Missing data for required field."]}'

    return {
        'errors': [
            {
                'code': INVALID_ARGUMENT,
                'message': 'Invalid JSON payload received. ' + message,
                'type': 'fatal'}
        ],
        'data': {}
    }


def test_respond_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt, invalid_json, invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'domain', 'value': 'cisco.com'}]

    if route.endswith('/trigger'):
        return {'action-id': 'valid-action-id',
                'observable_type': 'domain',
                'observable_value': 'cisco.com'}


def test_respond_call_success(route, client, valid_jwt, valid_json):
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
