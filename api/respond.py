from functools import partial

from flask import Blueprint, current_app

from api.client import AkamaiClient
from api.errors import InvalidArgumentError
from api.schemas import ObservableSchema, ActionFormParamsSchema
from api.utils import (
    get_json, get_jwt, jsonify_data, add_status, jsonify_result
)

respond_api = Blueprint('respond', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())

ADD_ACTION_ID = 'akamai-add-to-network-list'
REMOVE_ACTION_ID = 'akamai-remove-from-network-list'


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    type_name_map = current_app.config['AKAMAI_OBSERVABLES']

    observables = get_observables()
    observables = [ob for ob in observables if ob['type'] in type_name_map]

    credentials = get_jwt()
    client = AkamaiClient(credentials, current_app.config['USER_AGENT'])

    network_lists = client.network_lists()['networkLists']
    network_lists = [
        nl for nl in network_lists if nl.get('readOnly', False) is False
    ]

    def action(
        id_, title_template, description_template, observable, network_list
    ):
        type_name_map.get(observable['type'])

        return {
            'id': id_,
            'title': title_template.format(network_list["name"]),
            'description':
                description_template.format(
                    type_name_map.get(observable['type'])
                ),
            'categories': ['Akamai'],
            'query-params': {
                'observable_value': observable['value'],
                'observable_type': observable['type'],
                'network_list_id': network_list['uniqueId']
            }
        }

    def add_to(observable, network_list):
        return action(
            ADD_ACTION_ID,
            'Add to {}',
            'Add {} to Network List',
            observable,
            network_list
        )

    def remove_from(observable, network_list):
        return action(
            REMOVE_ACTION_ID,
            'Remove from {}',
            'Remove {} from Network List',
            observable,
            network_list
        )

    actions = []
    for observable in observables:
        for network_list in network_lists:

            if observable['value'] in network_list['list']:
                actions.append(remove_from(observable, network_list))
            else:
                actions.append(add_to(observable, network_list))

    return jsonify_data(actions)


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    add_status('failure')

    params = get_action_form_params()
    credentials = get_jwt()

    client = AkamaiClient(credentials, current_app.config['USER_AGENT'])
    action_map = {
        ADD_ACTION_ID: client.add_to_network_list,
        REMOVE_ACTION_ID: client.remove_from_network_list
    }

    action = action_map.get(params['action-id'])
    if not action:
        raise InvalidArgumentError("Unsupported action.")

    action(params['network_list_id'], params['observable_value'])

    add_status('success')
    return jsonify_result()
