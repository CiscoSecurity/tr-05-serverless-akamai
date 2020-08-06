from urllib.parse import urljoin

import requests
from akamai.edgegrid import EdgeGridAuth
from flask import Blueprint, current_app

from api.errors import CriticalAkamaiResponseError
from api.utils import get_jwt, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_jwt()
    s = requests.Session()
    s.auth = EdgeGridAuth(
        client_token=credentials['clientToken'],
        client_secret=credentials['clientSecret'],
        access_token=credentials['accessToken']
    )

    headers = {
        'Accept': 'application/json',
        'User-Agent': current_app.config['USER_AGENT']
    }

    url = urljoin(
            f'https://{credentials["baseUrl"]}',
            '/network-list/v2/network-lists?includeElements=true&listType=IP'
    )

    response = s.get(url, headers=headers)

    if not response.ok:
        raise CriticalAkamaiResponseError(response)

    return jsonify_data({'status': 'ok'})
