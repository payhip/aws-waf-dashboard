from __future__ import print_function

import json
import logging
import sys

import boto3
import requests
from crhelper import CfnResource
from furl import furl
from opensearchpy import OpenSearch, RequestsHttpConnection

from helpers.placeholder_resolver import resolve_placeholders
from helpers.service_settings import ServiceSettings
from helpers.solution_components import SolutionComponents

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
helper = CfnResource(json_logging=False, log_level='DEBUG', boto_level='CRITICAL')

try:
    aws_clients = {
        "waf": boto3.client('waf'),
        "wafRegional": boto3.client('waf-regional'),
        "wafv2_cloudfront": boto3.client('wafv2', region_name='us-east-1'),
        "wafv2_regional": boto3.client('wafv2'),
    }

    solution_components = SolutionComponents()
    service_settings = ServiceSettings(credentials=boto3.Session().get_credentials())

    logger.info("OpenSearch client URL %s", service_settings.host)

    opensearch_client = OpenSearch(
        hosts=[{'host': service_settings.host, 'port': 443}],
        http_auth=service_settings.aws_auth,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection)

except Exception as e:
    helper.init_failure(e)
    logging.error(e)
    raise e


@helper.create
def create(event=None, context=None):
    logger.info("Got Create!")
    logger.debug("Sourcing additional settings from the event")

    service_settings.source_settings_from_event(event)
    import_index_templates(solution_components.templates)
    # Purge any conflicting saved objects first (old copies with scripts)
    purge_existing_objects()
    # Recycle to ensure any existing saved objects are replaced with updated definitions
    recycle_dashboards_objects()
    # Permanently remove legacy scripted content and enforce correct fields
    try:
        remove_scripted_fields_from_index_pattern('awswaf-*')
        strip_scripts_from_saved_objects()
        enforce_terms_fields()
        set_legacy_maps_tile_url()
        normalize_fields_and_controls()
    except Exception as e:
        logger.warning("Post-create cleanup encountered an issue: %s", e)
    # Ensure the Data View picks up latest mappings automatically
    refresh_index_pattern_fields('awswaf-*')

    return "MyResourceId"


@helper.update
def update(event=None, context=None):
    logger.info("Got Update.")
    logger.debug("Sourcing additional settings from the event")

    # Support direct maintenance invoke when handler is lambda_function.update
    if isinstance(event, dict) and event.get('Action') == 'RefreshAndNormalize':
        logger.info("Direct maintenance via update(): recycle + normalize + refresh fields")
        try:
            service_settings.source_settings_from_event(event or {})
        except Exception:
            pass
        purge_existing_objects()
        recycle_dashboards_objects()
        try:
            remove_scripted_fields_from_index_pattern('awswaf-*')
            strip_scripts_from_saved_objects()
            enforce_terms_fields()
            set_legacy_maps_tile_url()
            normalize_fields_and_controls()
        except Exception as e:
            logger.warning("Direct maintenance cleanup (update) encountered an issue: %s", e)
        refresh_index_pattern_fields('awswaf-*')
        return {"status": "ok"}

    service_settings.source_settings_from_event(event)
    purge_existing_objects()
    recycle_dashboards_objects()
    try:
        remove_scripted_fields_from_index_pattern('awswaf-*')
        strip_scripts_from_saved_objects()
        enforce_terms_fields()
        set_legacy_maps_tile_url()
        normalize_fields_and_controls()
    except Exception as e:
        logger.warning("Post-update cleanup encountered an issue: %s", e)
    refresh_index_pattern_fields('awswaf-*')
    return "MyResourceId"


@helper.delete
def delete(event=None, context=None):
    logger.info("Got Delete")
    logger.debug("Sourcing additional settings from the event")

    try:
        service_settings.source_settings_from_event(event)
        try:
            delete_index_templates()
        except Exception as e:
            logger.warning("Ignoring error deleting index templates during stack delete: %s", e)
        try:
            delete_dashboards_objects()
        except Exception as e:
            logger.warning("Ignoring error deleting dashboards objects during stack delete: %s", e)
    except Exception as e:
        logger.warning("Ignoring delete-time initialization error: %s", e)
    # Always return success on Delete to prevent DELETE_FAILED if the domain no longer exists
    return True


@helper.poll_create
def poll_create(event=None, context=None):
    logger.info("Got create poll")
    return True


def handler(event, context):
    # Allow direct invocation to run maintenance without CloudFormation
    try:
        if isinstance(event, dict) and event.get('Action') == 'RefreshAndNormalize':
            logger.info("Running direct maintenance: recycle + normalize + refresh fields")
            try:
                # Ensure service settings are initialized from env
                service_settings.source_settings_from_event(event or {})
            except Exception:
                pass
            # Do the same steps as in create/update
            purge_existing_objects()
            recycle_dashboards_objects()
            try:
                remove_scripted_fields_from_index_pattern('awswaf-*')
                strip_scripts_from_saved_objects()
                enforce_terms_fields()
                set_legacy_maps_tile_url()
                normalize_fields_and_controls()
            except Exception as e:
                logger.warning("Direct maintenance cleanup encountered an issue: %s", e)
            refresh_index_pattern_fields('awswaf-*')
            return {"status": "ok"}
    except Exception as e:
        logger.warning("Direct maintenance path failed: %s", e)
    # Fallback to Custom Resource handler
    helper(event, context)


def action_dashboard_objects(method, ignored_objects=None):
    """
    Iterates through json objects in dashboards_definitions_json folder and makes API requests to OS Dashboards

    It's a generic method, that can take any HTTP verb and call OS Dashboards RESTful API.

    @param method: HTTP verb
    @param ignored_objects: A list of objects to ignore in this iteration, useful if we don't want to iterate through "visualizations" for example
    """
    logger.info(json.dumps(solution_components.__dict__, indent=4, sort_keys=True))

    if ignored_objects is None:
        ignored_objects = []

    for resource_type in vars(solution_components):
        logging.debug("TYPE: %s", resource_type)

        if resource_type == "templates" or resource_type in ignored_objects:
            continue
        else:
            for resource_name in solution_components.__getattribute__(resource_type):
                logging.debug("NAME: %s", resource_name)

                body = solution_components.__getattribute__(resource_type)[resource_name]

                if resource_type == "index_patterns":
                    body = resolve_placeholders(aws_clients, body)

                call_dashboards_api_for_resource(method, service_settings.dashboards_api_resource_types[resource_type], resource_name, body)


def call_dashboards_api_for_resource(method, resource_type, resource_name, resource_body):
    """
    Makes an actual HTTP request to OpenSearch Dashboards API

    The URL is constructed based on the arguments passed to this method and general settings stored in ServiceSettings object

    @param method: HTTP verb
    @param resource_type: type of OpenSearch resource, e.g. template/visualization/index_pattern
    @param resource_name: name of the resource to be created
    @param resource_body: stringified JSON body
    """
    f = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    f.add(path=['_dashboards', 'api', 'saved_objects', resource_type, resource_name])
    # Ensure we overwrite existing saved objects on POST to avoid stale field references
    if method.upper() == 'POST':
        f.add(query_params={'overwrite': 'true'})

    logging.info("Issuing %s to %s", method, f.url)

    response = requests.request(method, f.url, auth=service_settings.aws_auth, headers=service_settings.headers, data=resource_body)

    if response.ok:
        logging.info("Request was successful")
    elif response.status_code == 404:
        logging.info("Request made but the resource was not found")
    else:
        raise Exception(response.text)


def refresh_index_pattern_fields(title):
    """
    Programmatically refresh the Data View fields list to avoid stale field cache.
    Looks up the index-pattern saved object by title and calls refresh_fields.
    """
    # Find index-pattern id by title
    find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_url.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': title, 'per_page': 100})
    r = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        logger.warning("Index pattern search failed: %s", r.text)
        return
    results = r.json().get('saved_objects', [])
    if not results:
        logger.warning("Index pattern with title %s not found to refresh", title)
        return
    idx_id = results[0]['id']
    # POST refresh_fields
    ref_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    # Correct endpoint for OpenSearch Dashboards: /api/index_patterns/index_pattern/{id}/fields/refresh
    ref_url.add(path=['_dashboards', 'api', 'index_patterns', 'index_pattern', idx_id, 'fields', 'refresh'])
    r2 = requests.post(ref_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if r2.ok:
        logger.info("Refreshed fields for index-pattern %s", idx_id)
    else:
        logger.warning("Failed to refresh fields for index-pattern %s: %s", idx_id, r2.text)


def remove_scripted_fields_from_index_pattern(title):
    """Remove scripted fields from the specified Data View (index-pattern) by title."""
    # Find index-pattern id by title
    find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_url.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': title, 'per_page': 100})
    r = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        logger.warning("Index pattern search failed (scripted fields cleanup): %s", r.text)
        return
    results = r.json().get('saved_objects', [])
    if not results:
        logger.warning("Index pattern %s not found for scripted fields cleanup", title)
        return
    idx_id = results[0]['id']

    # Load full object
    get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    get_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
    g = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not g.ok:
        logger.warning("Failed to load index-pattern %s: %s", idx_id, g.text)
        return
    body = g.json()
    attrs = body.get('attributes', {})
    fields_raw = attrs.get('fields') or '[]'
    try:
        fields = json.loads(fields_raw)
    except Exception:
        fields = []
    # Remove any scripted fields entirely
    cleaned = [f for f in fields if not (isinstance(f, dict) and f.get('scripted') is True)]
    if len(cleaned) == len(fields):
        logger.info("No scripted fields present in data view %s", title)
    else:
        attrs['fields'] = json.dumps(cleaned)
        save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        save_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
        save_url.add(query_params={'overwrite': 'true'})
        s = requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                          data=json.dumps({'attributes': attrs, 'references': body.get('references', [])}))
        if s.ok:
            logger.info("Removed scripted fields from data view %s (%s)", title, idx_id)
        else:
            logger.warning("Failed to update data view %s: %s", idx_id, s.text)


def _strip_search_source_scripts(so_attrs):
    changed = False
    k = so_attrs.get('kibanaSavedObjectMeta') if isinstance(so_attrs, dict) else None
    if not (isinstance(k, dict) and isinstance(k.get('searchSourceJSON', None), str)):
        return changed, so_attrs
    try:
        ss = json.loads(k['searchSourceJSON'])
    except Exception:
        return changed, so_attrs
    # Remove script_fields
    if isinstance(ss.get('script_fields'), dict):
        del ss['script_fields']
        changed = True
    # Remove scripted filters from both keys that may be used
    for key in ['filter', 'filters']:
        if isinstance(ss.get(key), list):
            before = len(ss[key])
            ss[key] = [f for f in ss[key] if 'script' not in json.dumps(f or {})]
            if len(ss[key]) != before:
                changed = True
    # Normalize query
    if not isinstance(ss.get('query'), dict):
        ss['query'] = {'query': '', 'language': 'kuery'}
        changed = True
    k['searchSourceJSON'] = json.dumps(ss)
    so_attrs['kibanaSavedObjectMeta'] = k
    return changed, so_attrs


def strip_scripts_from_saved_objects():
    """Strip script_fields and scripted filters from all saved objects and unlink saved searches from visualizations."""
    types = ['search', 'visualization', 'dashboard']
    for t in types:
        find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_url.add(query_params={'type': t, 'per_page': 1000})
        rf = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not rf.ok:
            logger.warning("Failed to list %s: %s", t, rf.text)
            continue
        for obj in rf.json().get('saved_objects', []):
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', t, obj['id']])
            ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not ro.ok:
                continue
            full = ro.json()
            attrs = full.get('attributes', {})
            changed, attrs = _strip_search_source_scripts(attrs)
            if t == 'visualization':
                # Unlink saved search and remove agg scripts
                try:
                    vis_state = json.loads(attrs.get('visState', '{}'))
                    if isinstance(vis_state.get('params'), dict) and vis_state['params'].get('savedSearchId'):
                        del vis_state['params']['savedSearchId']
                        changed = True
                    if isinstance(vis_state.get('aggs'), list):
                        for a in vis_state['aggs']:
                            if isinstance(a, dict) and isinstance(a.get('params'), dict) and 'script' in a['params']:
                                del a['params']['script']
                                changed = True
                    attrs['visState'] = json.dumps(vis_state)
                except Exception:
                    pass
                # Remove references to searches
                if isinstance(full.get('references'), list) and any(r.get('type') == 'search' for r in full['references']):
                    full['references'] = [r for r in full['references'] if r.get('type') != 'search']
                    changed = True
            if changed:
                save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                save_url.add(path=['_dashboards', 'api', 'saved_objects', t, obj['id']])
                save_url.add(query_params={'overwrite': 'true'})
                requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))


def enforce_terms_fields():
    """Ensure key visualizations use canonical fields (no .keyword mistakes or scripts)."""
    field_map = {
        'httpRequest.clientIp.keyword': 'true_client_ip',
        'httpRequest.clientIp': 'true_client_ip',
        'httpRequest.country.keyword': 'real_country_code',
        'httpRequest.uri.keyword': 'uri',
        'httpRequest.httpMethod.keyword': 'httpMethod',
        'httpRequest.httpVersion.keyword': 'httpVersion',
        'method': 'httpMethod',
        'version': 'httpVersion',
        'httpRequest.host.keyword': 'host',
        'httpRequest.host': 'host',
        'Host': 'host',
        # Ensure action uses the canonical keyword field name present in Data View
        'action.keyword': 'action',
        'action': 'action'
    }
    targets = {
        'Top 10 User-Agents': 'UserAgent',
        'Top 10 Hosts': 'host',
        'Top 10 Rules': 'rule',
        'Top 10 WebACL': 'webacl',
        'Top 10 URI': 'uri',
        'Top 10 IP Addresses': 'true_client_ip'
    }
    for title, field in targets.items():
        # find by title
        find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_vis.add(query_params={'type': 'visualization', 'searchFields': 'title', 'search': title, 'per_page': 100})
        rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not rv.ok:
            continue
        for obj in rv.json().get('saved_objects', []):
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
            ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not ro.ok:
                continue
            full = ro.json()
            attrs = full.get('attributes', {})
            try:
                vis_state = json.loads(attrs.get('visState', '{}'))
                changed = False
                for a in vis_state.get('aggs', []):
                    params = a.get('params', {}) if isinstance(a, dict) else {}
                    f = params.get('field')
                    if f in field_map and field_map[f] != f:
                        params['field'] = field_map[f]
                        a['params'] = params
                        changed = True
                    # Normalize action to canonical name if applicable
                    if f == 'action':
                        params['field'] = 'action'
                        a['params'] = params
                        changed = True
                if changed:
                    attrs['visState'] = json.dumps(vis_state)
                    save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                    save_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                    save_url.add(query_params={'overwrite': 'true'})
                    requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                                  data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))
            except Exception:
                continue


def normalize_fields_and_controls():
    """Rewrite legacy httpRequest.* fields to canonical ones across all visualizations and Filters control."""
    field_map = {
        'httpRequest.clientIp.keyword': 'true_client_ip',
        'httpRequest.clientIp': 'true_client_ip',
        'httpRequest.country.keyword': 'real_country_code',
        'httpRequest.uri.keyword': 'uri',
        'httpRequest.httpMethod.keyword': 'httpMethod',
        'httpRequest.httpVersion.keyword': 'httpVersion',
        'method': 'httpMethod',
        'version': 'httpVersion',
        'httpRequest.host.keyword': 'host',
        'httpRequest.host': 'host',
        'Host': 'host',
        'action.keyword': 'action',
        'action': 'action'
    }

    # Update all visualizations' fields (any agg.param.field)
    find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_vis.add(query_params={'type': 'visualization', 'per_page': 1000})
    rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if rv.ok:
        for obj in rv.json().get('saved_objects', []):
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
            ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not ro.ok:
                continue
            full = ro.json()
            attrs = full.get('attributes', {})
            changed = False
            try:
                vis_state = json.loads(attrs.get('visState', '{}'))
                for a in vis_state.get('aggs', []):
                    if not isinstance(a, dict):
                        continue
                    params = a.get('params', {}) if isinstance(a.get('params'), dict) else {}
                    f = params.get('field')
                    if f in field_map and field_map[f] != f:
                        params['field'] = field_map[f]
                        a['params'] = params
                        changed = True
                    if f == 'action':
                        params['field'] = 'action'
                        a['params'] = params
                        changed = True
                if changed:
                    attrs['visState'] = json.dumps(vis_state)
            except Exception:
                changed = False
            if changed:
                save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                save_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                save_url.add(query_params={'overwrite': 'true'})
                requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))

    # Update Filters control by title
    try:
        find_filters = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_filters.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_filters.add(query_params={'type': 'visualization', 'search_fields': 'title', 'search': 'Filters', 'per_page': 100})
        rf = requests.get(find_filters.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        for obj in (rf.json().get('saved_objects', []) if rf.ok else []):
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
            ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not ro.ok:
                continue
            full = ro.json()
            attrs = full.get('attributes', {})
            changed = False
            try:
                vis_state = json.loads(attrs.get('visState', '{}'))
                controls = vis_state.get('params', {}).get('controls', [])
                for c in controls:
                    fname = (c.get('fieldName') or c.get('field_name')) if isinstance(c, dict) else None
                    if fname in field_map:
                        c['fieldName'] = field_map[fname]
                        changed = True
                    if fname == 'action':
                        c['fieldName'] = 'action'
                        changed = True
                if changed:
                    vis_state.setdefault('params', {})['controls'] = controls
                    attrs['visState'] = json.dumps(vis_state)
            except Exception:
                changed = False
            if changed:
                save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                save_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                save_url.add(query_params={'overwrite': 'true'})
                requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))
    except Exception as e:
        logger.warning("Filters normalization failed: %s", e)

def set_legacy_maps_tile_url():
    """Prevent legacy Maps errors by setting a default OSM tile URL in Advanced Settings."""
    url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    url.add(path=['_dashboards', 'api', 'kibana', 'settings'])
    payload = {
        'changes': {
            'map.tilemap.url': 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
            'map.tilemap.options.attribution': ' OpenStreetMap contributors'
        }
    }
    try:
        r = requests.post(url.url, auth=service_settings.aws_auth, headers=service_settings.headers, data=json.dumps(payload))
        if r.ok:
            logger.info("Set legacy map tile URL in Advanced Settings")
        else:
            logger.warning("Failed to set legacy map tile URL: %s", r.text)
    except Exception as e:
        logger.warning("Advanced settings update not supported or failed: %s", e)


def purge_existing_objects():
    """Remove any conflicting saved objects by title to prevent stale scripted configs."""
    # Delete all index-patterns with title awswaf-*
    find_ip = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_ip.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_ip.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': 'awswaf-*', 'per_page': 100})
    r = requests.get(find_ip.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if r.ok:
        for obj in r.json().get('saved_objects', []):
            del_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            del_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', obj['id']])
            requests.delete(del_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)

    # Delete dashboard titled WAFDashboard
    find_dash = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_dash.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_dash.add(query_params={'type': 'dashboard', 'searchFields': 'title', 'search': 'WAFDashboard', 'per_page': 100})
    r2 = requests.get(find_dash.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if r2.ok:
        for obj in r2.json().get('saved_objects', []):
            del_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            del_url.add(path=['_dashboards', 'api', 'saved_objects', 'dashboard', obj['id']])
            requests.delete(del_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)

    # Delete visualizations we manage (by known titles)
    vis_titles = [
        'HTTP Methods','HTTP Versions','Top 10 URI','Top 10 Hosts','Top 10 WebACL',
        'Top 10 User-Agents','Executed WAF Rules','Countries By Number of Request',
        'All vs Blocked Requests','Requests Count','Unique IP Count','Top 10 IP Addresses',
        'Top 10 Countries','Top 10 Rules'
    ]
    for t in vis_titles:
        find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_vis.add(query_params={'type': 'visualization', 'searchFields': 'title', 'search': t, 'per_page': 100})
        rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if rv.ok:
            for obj in rv.json().get('saved_objects', []):
                del_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                del_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                requests.delete(del_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)


def import_index_templates(templates):
    """
    Imports index_templates to OpenSearch directly

    This method uses OpenSearch SDK client to make the call.
    @param templates: stringified JSON body
    """
    logger.info("Firing index_template")

    for template in templates:
        result = opensearch_client.indices.put_index_template("awswaf-logs",
                                                              body=templates[template],
                                                              params={'create': 'false', 'cause': 'Initial templates creation'})
        logging.info(result)


def delete_index_templates():
    """
    Removes ALL index templates in OpenSearch - USE WITH CAUTION
    """
    result = opensearch_client.indices.get_index_template()
    for template in result['index_templates']:
        opensearch_client.indices.delete_index_template(name=template["name"])


def recycle_dashboards_objects():
    """
    Recycles OpenSearch Dashboard items by first deleting them and next recreates them one by one.

    It might be useful to call this method to update some of the resolved strings in JSON documents
    """
    action_dashboard_objects('DELETE')
    action_dashboard_objects('POST')


def delete_dashboards_objects():
    action_dashboard_objects('DELETE')


def main():
    print("Hello World!")
    delete()


if __name__ == "__main__":
    main()
