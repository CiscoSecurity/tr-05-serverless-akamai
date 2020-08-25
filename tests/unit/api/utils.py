def headers(jwt):
    return {'Authorization': f'Bearer {jwt}'}


def check_akamai_request(
        request_mock, params, method='GET',
        uri='https://xxx/network-list/v2/network-lists'
):
    request_mock.assert_called_once_with(
        method,
        uri,
        headers={'Accept': 'application/json',
                 'User-Agent': 'Cisco Threat Response Integrations'
                               ' <tr-integrations-support@cisco.com>'},
        params=params
    )
