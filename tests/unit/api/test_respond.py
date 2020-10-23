from collections import namedtuple
from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests import Session
from requests.exceptions import SSLError

from api.errors import INVALID_ARGUMENT
from api.respond import ADD_ACTION_ID, REMOVE_ACTION_ID
from .utils import headers, check_akamai_request


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
        return {'action-id': ADD_ACTION_ID,
                'observable_type': 'ip',
                'observable_value': '1.1.1.1',
                'network_list_id': 'nli'}


def test_respond_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_respond_call_with_wrong_authorization_type(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt, auth_type='wrong_type'),
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_respond_call_with_wrong_jwt_structure(
        route, client, wrong_jwt_structure, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(wrong_jwt_structure), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_respond_call_with_jwt_encoded_by_wrong_key(
        route, client, invalid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(invalid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Failed to decode JWT with provided key'
    )


def test_respond_call_with_wrong_jwt_payload_structure(
        route, client, wrong_payload_structure_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, headers=headers(wrong_payload_structure_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


def test_respond_call_with_missed_secret_key(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    right_secret_key = client.application.secret_key
    client.application.secret_key = None
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    client.application.secret_key = right_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        '<SECRET_KEY> is missing'
    )


def test_respond_call_with_unauthorized_creds(
        route, client, valid_jwt, valid_json,
        akamai_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_unauthorized_creds

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload


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
    data = {}

    if route.endswith('/observables'):
        message = '{"0": {"value": ["Missing data for required field."]}}'
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
    response = client.post(
        route, headers=headers(valid_jwt), json=invalid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


def test_respond_call_with_ssl_error(
        route, client, valid_jwt, valid_json,
        sslerror_expected_payload
):
    with patch.object(Session, 'request') as request_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        request_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_respond_observables_call_success(
        client, valid_jwt, akamai_response_network_lists,
        respond_observables_expected_payload
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_network_lists

        response = client.post(
            '/respond/observables', headers=headers(valid_jwt),
            json=[{'type': 'ip', 'value': '1.1.1.1'},
                  {'type': 'domain', 'value': 'cisco.com'}]
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == respond_observables_expected_payload
        check_akamai_request(
            request_mock,  {'listType': 'IP', 'includeElements': True}
        )


def input_sets():
    input_json = {'observable_type': 'ip',
                  'observable_value': '1.1.1.1',
                  'network_list_id': 'nli'}
    uri = 'https://xxx/network-list/v2/network-lists/nli/elements'
    params = {'element': '1.1.1.1'}
    expected_response_success = {'data': {'status': 'success'}}

    TestData = namedtuple(
        'TestData', 'test_name json expected_response request_check'
    )
    yield TestData(
        'add_action_success',
        {**input_json, 'action-id': ADD_ACTION_ID},
        expected_response_success,
        lambda request_mock: check_akamai_request(
            request_mock,  params, method='PUT', uri=uri
        )
    )

    yield TestData(
        'remove_action_success',
        {**input_json, 'action-id': REMOVE_ACTION_ID},
        expected_response_success,
        lambda request_mock: check_akamai_request(
            request_mock, params, method='DELETE', uri=uri
        )
    )

    yield TestData(
        'unsupported_action_failure',
        {**input_json, 'action-id': 'unknown'},
        {
            'data': {'status': 'failure'},
            'errors': [
                {'code': INVALID_ARGUMENT,
                 'message': 'Unsupported action.',
                 'type': 'fatal'}
            ]
        },
        lambda r: r.assert_not_called()
    )


@fixture(scope='module', params=input_sets(), ids=lambda d: d.test_name)
def input_data(request):
    return request.param


def test_respond_trigger(
        input_data, client, valid_jwt, akamai_response_ok
):
    with patch.object(Session, 'request') as request_mock:
        request_mock.return_value = akamai_response_ok

        response = client.post(
            '/respond/trigger', headers=headers(valid_jwt),
            json=input_data.json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == input_data.expected_response
        input_data.request_check(request_mock)
