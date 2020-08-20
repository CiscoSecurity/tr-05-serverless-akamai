from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests import Session

from api.errors import INVALID_ARGUMENT
from .utils import headers


def routes():
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'ip', 'value': '1.1.1.1'}]

    if route.endswith('/trigger'):
        return {'action-id': 'valid-action-id',
                'observable_type': 'ip',
                'observable_value': '1.1.1.1',
                'network_list_id': 'nli'}


def test_respond_call_with_invalid_jwt_failure(
        route, client, valid_json, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(
        route, headers=headers(invalid_jwt), json=valid_json
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@fixture(scope='module')
def invalid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'ip'}]

    if route.endswith('/trigger'):
        return {'observable_type': 'ip',
                'observable_value': '1.1.1.1',
                'network_list_id': 'nli'}


@fixture(scope='module')
def invalid_json_expected_payload(route):
    message = None
    if route.endswith('/observables'):
        message = '{"0": {"value": ["Missing data for required field."]}}'
        data = {}
    if route.endswith('/trigger'):
        message = '{"action-id": ["Missing data for required field."]}'
        data = {'status': 'failure'}

    return {
        'errors': [
            {
                'code': INVALID_ARGUMENT,
                'message': 'Invalid JSON payload received. ' + message,
                'type': 'fatal'}
        ],
        'data': data
    }


def test_respond_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt, invalid_json, invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


def test_respond_call_success(
        route, client, valid_jwt, valid_json, akamai_response_network_lists
):
    with patch.object(Session, 'request') as get_mock:
        get_mock.return_value = akamai_response_network_lists
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )
        assert response.status_code == HTTPStatus.OK
