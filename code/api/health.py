from flask import Blueprint, current_app

from api.client import AkamaiClient
from api.utils import get_jwt, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_jwt()
    client = AkamaiClient(credentials, current_app.config['USER_AGENT'])

    _ = client.network_lists(include_elements=False)

    return jsonify_data({'status': 'ok'})
