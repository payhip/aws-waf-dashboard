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
    try:
        service_settings.source_settings_from_event(event)
        import_index_templates(solution_components.templates)
        # Run across multiple tenant headers to ensure coverage of user view
        for tenant in [None, 'global', 'global_tenant', 'private', '__user__']:
            if tenant is not None:
                service_settings.headers['securitytenant'] = tenant
            else:
                service_settings.headers.pop('securitytenant', None)
            logger.info("Running create flow for tenant=%s", tenant)
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
                fix_dashboard_panels_and_visuals()
                fix_dashboard_panel_titles()
            except Exception as e:
                logger.warning("Post-create cleanup encountered an issue (tenant=%s): %s", tenant, e)
        # Ensure the Data View picks up latest mappings automatically
        refresh_index_pattern_fields('awswaf-*')
    except Exception as e:
        logger.error("Create flow encountered an error but will return SUCCESS: %s", e)

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
        for tenant in [None, 'global', 'global_tenant', 'private', '__user__']:
            if tenant is not None:
                service_settings.headers['securitytenant'] = tenant
            else:
                service_settings.headers.pop('securitytenant', None)
            logger.info("Direct maintenance via update() for tenant=%s", tenant)
            purge_existing_objects()
            recycle_dashboards_objects()
            try:
                remove_scripted_fields_from_index_pattern('awswaf-*')
                strip_scripts_from_saved_objects()
                enforce_terms_fields()
                set_legacy_maps_tile_url()
                normalize_fields_and_controls()
                fix_dashboard_panel_titles()
            except Exception as e:
                logger.warning("Direct maintenance cleanup (update) encountered an issue (tenant=%s): %s", tenant, e)
        refresh_index_pattern_fields('awswaf-*')
        return {"status": "ok"}

    try:
        service_settings.source_settings_from_event(event)
        for tenant in [None, 'global', 'global_tenant', 'private', '__user__']:
            if tenant is not None:
                service_settings.headers['securitytenant'] = tenant
            else:
                service_settings.headers.pop('securitytenant', None)
            logger.info("Running update flow for tenant=%s", tenant)
            purge_existing_objects()
            recycle_dashboards_objects()
            try:
                remove_scripted_fields_from_index_pattern('awswaf-*')
                strip_scripts_from_saved_objects()
                enforce_terms_fields()
                set_legacy_maps_tile_url()
                normalize_fields_and_controls()
                fix_dashboard_panel_titles()
            except Exception as e:
                logger.warning("Post-update cleanup encountered an issue (tenant=%s): %s", tenant, e)
        refresh_index_pattern_fields('awswaf-*')
    except Exception as e:
        logger.error("Update flow encountered an error but will return SUCCESS: %s", e)
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
            for tenant in [None, 'global', 'global_tenant', 'private', '__user__']:
                if tenant is not None:
                    service_settings.headers['securitytenant'] = tenant
                else:
                    service_settings.headers.pop('securitytenant', None)
                logger.info("Direct maintenance via handler() for tenant=%s", tenant)
                purge_existing_objects()
                recycle_dashboards_objects()
                try:
                    remove_scripted_fields_from_index_pattern('awswaf-*')
                    strip_scripts_from_saved_objects()
                    enforce_terms_fields()
                    set_legacy_maps_tile_url()
                    normalize_fields_and_controls()
                    fix_dashboard_panels_and_visuals()
                    fix_dashboard_panel_titles()
                except Exception as e:
                    logger.warning("Direct maintenance cleanup encountered an issue (tenant=%s): %s", tenant, e)
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

    # Ensure we only send valid JSON payloads; skip invalid ones to prevent 400s
    payload = None
    try:
        payload = json.loads(resource_body) if isinstance(resource_body, str) else resource_body
    except Exception:
        logger.warning("Skipping invalid JSON payload for %s/%s", resource_type, resource_name)
        return

    # Normalize shape expected by OpenSearch Dashboards saved_objects API
    final_payload = payload
    if isinstance(payload, dict):
        if 'attributes' in payload:
            final_payload = {
                'attributes': payload.get('attributes', {}),
                'references': payload.get('references', [])
            }
        else:
            # If it's likely a raw attributes object (e.g., has title/visState), wrap it
            likely_attrs_keys = {'title', 'visState', 'kibanaSavedObjectMeta', 'attributes'}
            if any(k in payload for k in likely_attrs_keys):
                final_payload = {
                    'attributes': payload,
                    'references': []
                }

    try:
        snippet = json.dumps(final_payload)[:500]
    except Exception:
        snippet = str(type(final_payload))
    logging.info("Saved object request: type=%s id=%s payload_snippet=%s", resource_type, resource_name, snippet)

    response = requests.request(method, f.url, auth=service_settings.aws_auth, headers=service_settings.headers, json=final_payload)

    if response.ok:
        logging.info("Request was successful")
    elif response.status_code == 404:
        logging.info("Request made but the resource was not found")
    elif response.status_code == 400:
        logging.error("Saved object request returned 400; skipping object. body=%s", response.text)
        return
    else:
        logging.error("Saved object request failed: status=%s body=%s", response.status_code, response.text)
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
    if not r2.ok:
        logger.warning("Failed to refresh fields for index-pattern %s: %s", idx_id, r2.text)
        return
    logger.info("Refreshed fields for index-pattern %s (%s)", title, idx_id)


def ensure_runtime_fields_on_index_pattern(title):
    """Ensure runtime fields exist on the Data View for header-derived values.
    - req_true_client_ip: from headers True-Client-IP or fallback X-Forwarded-For first hop
    - req_country_code: from headers section-io-geo-country-code
    - req_asn: from headers section-io-geo-asn
    """
    # 1) Find index-pattern id by title
    find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_url.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': title, 'per_page': 100})
    r = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        logger.warning("Index pattern search (for runtime fields) failed: %s", r.text)
        return
    results = r.json().get('saved_objects', [])
    if not results:
        logger.warning("Index pattern with title %s not found for runtime fields", title)
        return
    ip = results[0]
    idx_id = ip['id']

    # 2) Get full saved object to merge runtimeFieldMap
    get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    get_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
    g = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not g.ok:
        logger.warning("Failed to get index-pattern %s for runtime fields: %s", idx_id, g.text)
        return
    obj = g.json()
    attrs = obj.get('attributes', {}) if isinstance(obj, dict) else {}
    runtime_map = attrs.get('runtimeFieldMap') or {}
    if isinstance(runtime_map, str):
        try:
            runtime_map = json.loads(runtime_map)
        except Exception:
            runtime_map = {}

    # 3) Ensure required runtime fields
    required = {
        'req_true_client_ip': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String ip = null;"
                    "for (def h : params._source.httpRequest.headers) { if (h.name != null && h.name.equalsIgnoreCase('True-Client-IP')) { ip = h.value; break; } }"
                    "if (ip == null) { for (def h : params._source.httpRequest.headers) { if (h.name != null && h.name.equalsIgnoreCase('X-Forwarded-For') && h.value != null) { int comma = h.value.indexOf(','); ip = comma > 0 ? h.value.substring(0, comma).trim() : h.value.trim(); break; } } }"
                    "emit(ip);"
                )
            }
        },
        'req_country_code': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String cc = null; for (def h : params._source.httpRequest.headers) { if (h.name != null && h.name.equalsIgnoreCase('section-io-geo-country-code')) { cc = h.value; break; } } emit(cc);"
                )
            }
        },
        'req_asn': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String asn = null; for (def h : params._source.httpRequest.headers) { if (h.name != null && h.name.equalsIgnoreCase('section-io-geo-asn')) { asn = h.value; break; } } emit(asn);"
                )
            }
        }
    }

    changed = False
    for k, v in required.items():
        if k not in runtime_map:
            runtime_map[k] = v
            changed = True

    if not changed:
        logger.info("Runtime fields already present on %s", idx_id)
        return

    # 4) Update saved object with merged runtimeFieldMap
    put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    put_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
    payload = { 'attributes': { 'title': attrs.get('title'), 'runtimeFieldMap': runtime_map } }
    p = requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers, json=payload)
    if not p.ok:
        logger.warning("Failed to update runtime fields on %s: %s", idx_id, p.text)
        return
    logger.info("Added runtime fields to index-pattern %s", idx_id)


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
    """Ensure key visualizations use canonical fields and Top 20 sizing.

    - Convert legacy fields to canonical ones.
    - For specific visualizations, enforce terms size/perPage=20.
    - Migrate WebACL panel to ASN (req_asn) and rename to Top 20 ASN.
    """
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
    # Define enforced field mapping and new sizes for our target visualizations
    targets = {
        'Top 10 User-Agents': {'field': 'UserAgent', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 User-Agents'},
        'Top 10 Hosts': {'field': 'host', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 Hosts'},
        'Top 10 Rules': {'field': 'rule', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 Rules'},
        # Will be migrated to ASN with new title below
        'Top 10 WebACL': {'field': 'webacl', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 ASN'},
        'Top 10 URI': {'field': 'uri', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 URI'},
        'Top 10 IP Addresses': {'field': 'true_client_ip', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 IP Addresses'},
        'Top 10 Countries': {'field': 'real_country_code', 'size': 20, 'perPage': 20, 'new_title': 'Top 20 Countries'},
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
                # Enforce Top 20 for table visualizations (params.perPage) when we recognize the title
                cfg = targets.get(title)
                if cfg and isinstance(vis_state.get('params'), dict):
                    if vis_state['params'].get('perPage') != cfg['perPage']:
                        vis_state['params']['perPage'] = cfg['perPage']
                        changed = True
                # Also rename title to Top 20 variant
                if cfg and attrs.get('title') != cfg.get('new_title') and cfg.get('new_title'):
                    attrs['title'] = cfg['new_title']
                    # Update visState title if present
                    try:
                        if isinstance(vis_state, dict) and vis_state.get('title'):
                            vis_state['title'] = cfg['new_title']
                    except Exception:
                        pass
                    changed = True

                for a in vis_state.get('aggs', []):
                    params = a.get('params', {}) if isinstance(a, dict) else {}
                    f = params.get('field')
                    # Normalize legacy -> canonical
                    if f in field_map and field_map[f] != f:
                        params['field'] = field_map[f]
                        a['params'] = params
                        changed = True
                    # Normalize action to canonical name if applicable
                    if f == 'action':
                        params['field'] = 'action'
                        a['params'] = params
                        changed = True
                    # Enforce terms bucket size (Top 20)
                    if cfg and a.get('type') == 'terms':
                        if params.get('size') != cfg['size']:
                            params['size'] = cfg['size']
                            a['params'] = params
                            changed = True

                    # Migrate WebACL panel to ASN with new title
                    if title == 'Top 10 WebACL' and a.get('type') == 'terms':
                        # Switch field to req_asn and rename visualization title
                        if params.get('field') != 'req_asn':
                            params['field'] = 'req_asn'
                            a['params'] = params
                            changed = True
                        if attrs.get('title') != 'Top 20 ASN':
                            attrs['title'] = 'Top 20 ASN'
                            changed = True

                    # Migrate IP/Country panels to new req_* fields
                    if title == 'Top 10 IP Addresses' and a.get('type') == 'terms':
                        if params.get('field') != 'req_true_client_ip':
                            params['field'] = 'req_true_client_ip'
                            a['params'] = params
                            changed = True
                    if title == 'Top 10 Countries' and a.get('type') == 'terms':
                        if params.get('field') != 'req_country_code':
                            params['field'] = 'req_country_code'
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

    # Also enforce by known IDs in case title search misses or stale objects persist
    id_targets = {
        'top10ip':        {'new_title': 'Top 20 IP Addresses', 'field': 'req_true_client_ip', 'size': 20, 'perPage': 20},
        'top10countries': {'new_title': 'Top 20 Countries',    'field': 'req_country_code',   'size': 20, 'perPage': 20},
        'top10webacl':    {'new_title': 'Top 20 ASN',          'field': 'req_asn',            'size': 20, 'perPage': 20},
        'top10hosts':     {'new_title': 'Top 20 Hosts',        'field': 'host',               'size': 20, 'perPage': 20},
        'top10uris':      {'new_title': 'Top 20 URI',          'field': 'uri',                'size': 20, 'perPage': 20},
        'top10useragents':{'new_title': 'Top 20 User-Agents',  'field': 'UserAgent',          'size': 20, 'perPage': 20},
        'top10rules':     {'new_title': 'Top 20 Rules',        'field': 'rule',               'size': 20, 'perPage': 20},
    }
    for vid, cfg in id_targets.items():
        try:
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not ro.ok:
                continue
            full = ro.json()
            attrs = full.get('attributes', {})
            vis_state = json.loads(attrs.get('visState', '{}'))
            changed = False
            # Title
            if cfg.get('new_title') and attrs.get('title') != cfg['new_title']:
                attrs['title'] = cfg['new_title']
                if isinstance(vis_state, dict):
                    vis_state['title'] = cfg['new_title']
                changed = True
            # Per-page
            if isinstance(vis_state.get('params'), dict) and vis_state['params'].get('perPage') != cfg['perPage']:
                vis_state['params']['perPage'] = cfg['perPage']
                changed = True
            # Aggs
            for a in vis_state.get('aggs', []):
                if a.get('type') == 'terms':
                    p = a.get('params', {})
                    if p.get('size') != cfg['size']:
                        p['size'] = cfg['size']
                        a['params'] = p
                        changed = True
                    if p.get('field') != cfg['field']:
                        p['field'] = cfg['field']
                        a['params'] = p
                        changed = True
            if changed:
                attrs['visState'] = json.dumps(vis_state)
                save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                save_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
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
        'action': 'action',
        # Migrate legacy to new req_* canonical fields
        'true_client_ip': 'req_true_client_ip',
        'real_country_code': 'req_country_code'
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
                # Force table/page size to 20 wherever applicable
                if isinstance(vis_state.get('params'), dict) and vis_state.get('type') == 'table':
                    if vis_state['params'].get('perPage') != 20:
                        vis_state['params']['perPage'] = 20
                        changed = True

                # Standardize titles 'Top 10 ' -> 'Top 20 '
                if isinstance(vis_state, dict) and isinstance(vis_state.get('title'), str) and vis_state['title'].startswith('Top 10 '):
                    vis_state['title'] = 'Top 20 ' + vis_state['title'][7:]
                    attrs['title'] = vis_state['title']
                    changed = True

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
                    # Enforce terms size=20 for all visuals
                    if a.get('type') == 'terms' and params.get('size') != 20:
                        params['size'] = 20
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

def fix_dashboard_panel_titles():
    """Rewrite dashboard panelsJSON to remove/replace any panel-level 'Top 10' titles with 'Top 20'.
    Targets known visualization IDs and sets the correct title in the dashboard tile.
    """
    mappings = {
        'top10ip': 'Top 20 IP Addresses',
        'top10countries': 'Top 20 Countries',
        'top10webacl': 'Top 20 ASN',
        'top10hosts': 'Top 20 Hosts',
        'top10uris': 'Top 20 URI',
        'top10useragents': 'Top 20 User-Agents',
        'top10rules': 'Top 20 Rules',
    }
    # Find dashboards (default WAFDashboard)
    find_dash = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_dash.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_dash.add(query_params={'type': 'dashboard', 'per_page': 1000})
    r = requests.get(find_dash.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        return
    for d in r.json().get('saved_objects', []):
        get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        get_url.add(path=['_dashboards', 'api', 'saved_objects', 'dashboard', d['id']])
        ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not ro.ok:
            continue
        full = ro.json()
        attrs = full.get('attributes', {})
        panels_raw = attrs.get('panelsJSON', '[]')
        try:
            panels = json.loads(panels_raw)
        except Exception:
            continue
        changed = False
        for p in panels:
            vid = p.get('id')
            if vid in mappings:
                ec = p.setdefault('embeddableConfig', {})
                title_now = ec.get('title')
                if title_now != mappings[vid]:
                    ec['title'] = mappings[vid]
                    changed = True
        if changed:
            attrs['panelsJSON'] = json.dumps(panels)
            save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            save_url.add(path=['_dashboards', 'api', 'saved_objects', 'dashboard', d['id']])
            save_url.add(query_params={'overwrite': 'true'})
            requests.post(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                          data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))

def fix_dashboard_panels_and_visuals():
    """Locate the 'WAFDashboard', iterate its panels, force-update the referenced visualizations
    with field migrations and 20/20 sizing, and also set tile titles to 'Top 20 ...'.
    """
    # Find WAFDashboard by title
    find_dash = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_dash.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_dash.add(query_params={'type': 'dashboard', 'searchFields': 'title', 'search': 'WAFDashboard', 'per_page': 50})
    r = requests.get(find_dash.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        return
    targets = {
        'top10ip':        {'new_title': 'Top 20 IP Addresses', 'field': 'req_true_client_ip'},
        'top10countries': {'new_title': 'Top 20 Countries',    'field': 'req_country_code'},
        'top10webacl':    {'new_title': 'Top 20 ASN',          'field': 'req_asn'},
        'top10hosts':     {'new_title': 'Top 20 Hosts',        'field': 'host'},
        'top10uris':      {'new_title': 'Top 20 URI',          'field': 'uri'},
        'top10useragents':{'new_title': 'Top 20 User-Agents',  'field': 'UserAgent'},
        'top10rules':     {'new_title': 'Top 20 Rules',        'field': 'rule'},
    }
    for d in r.json().get('saved_objects', []):
        get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        get_url.add(path=['_dashboards', 'api', 'saved_objects', 'dashboard', d['id']])
        ro = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not ro.ok:
            continue
        full = ro.json()
        attrs = full.get('attributes', {})
        panels = []
        try:
            panels = json.loads(attrs.get('panelsJSON', '[]'))
        except Exception:
            pass
        changed_dash = False
        for p in panels:
            vid = p.get('id')
            if not vid:
                continue
            # Update the visualization itself
            gv = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            gv.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            rv = requests.get(gv.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not rv.ok:
                continue
            vfull = rv.json()
            vattrs = vfull.get('attributes', {})
            try:
                vstate = json.loads(vattrs.get('visState', '{}'))
            except Exception:
                vstate = {}
            vchanged = False
            if isinstance(vstate.get('params'), dict) and vstate.get('type') == 'table':
                if vstate['params'].get('perPage') != 20:
                    vstate['params']['perPage'] = 20
                    vchanged = True
            for a in vstate.get('aggs', []) or []:
                if not isinstance(a, dict):
                    continue
                params = a.get('params', {}) if isinstance(a.get('params'), dict) else {}
                if a.get('type') == 'terms':
                    if params.get('size') != 20:
                        params['size'] = 20
                        a['params'] = params
                        vchanged = True
                f = params.get('field')
                # global field_map
                fmap = {
                    'true_client_ip': 'req_true_client_ip',
                    'real_country_code': 'req_country_code',
                    'httpRequest.clientIp': 'true_client_ip',
                    'httpRequest.clientIp.keyword': 'true_client_ip',
                    'httpRequest.country.keyword': 'real_country_code'
                }
                if f in fmap:
                    params['field'] = fmap[f]
                    a['params'] = params
                    vchanged = True
                # if the vid is one of our targets, enforce its canonical field
                if vid in targets and a.get('type') == 'terms':
                    tf = targets[vid]['field']
                    if params.get('field') != tf:
                        params['field'] = tf
                        a['params'] = params
                        vchanged = True
            # Standardize titles
            if isinstance(vstate, dict) and isinstance(vstate.get('title'), str) and vstate['title'].startswith('Top 10 '):
                vstate['title'] = 'Top 20 ' + vstate['title'][7:]
                vattrs['title'] = vstate['title']
                vchanged = True
            if vid in targets and vattrs.get('title') != targets[vid]['new_title']:
                vattrs['title'] = targets[vid]['new_title']
                if isinstance(vstate, dict):
                    vstate['title'] = targets[vid]['new_title']
                vchanged = True
            if vchanged:
                vattrs['visState'] = json.dumps(vstate)
                sv = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                sv.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
                sv.add(query_params={'overwrite': 'true'})
                requests.post(sv.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              data=json.dumps({'attributes': vattrs, 'references': vfull.get('references', [])}))
            # Update tile title
            if vid in targets:
                ec = p.setdefault('embeddableConfig', {})
                if ec.get('title') != targets[vid]['new_title']:
                    ec['title'] = targets[vid]['new_title']
                    changed_dash = True
        if changed_dash:
            attrs['panelsJSON'] = json.dumps(panels)
            sd = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            sd.add(path=['_dashboards', 'api', 'saved_objects', 'dashboard', d['id']])
            sd.add(query_params={'overwrite': 'true'})
            requests.post(sd.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                          data=json.dumps({'attributes': attrs, 'references': full.get('references', [])}))

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
            logger.info("Set legacy map tile URL")
            run_terms_diagnostics()
        else:
            logger.warning("Failed to set legacy map tile URL: %s", r.text)
    except Exception as e:
        logger.warning("Advanced settings update not supported or failed: %s", e)

def run_terms_diagnostics():
    """Run terms aggs (size=50) for key fields to confirm >10 buckets are available.
    Logs bucket counts and top keys for quick validation.
    """
    fields = [
        'req_true_client_ip', 'req_country_code', 'req_asn',
        'host', 'uri', 'UserAgent', 'rule'
    ]
    body = {
        'size': 0,
        'aggs': { f'a_{i}': { 'terms': { 'field': f, 'size': 50, 'order': { '_count': 'desc' } } } for i, f in enumerate(fields) }
    }
    try:
        res = opensearch_client.search(index='awswaf-*', body=body)
        aggs = res.get('aggregations', {})
        for i, f in enumerate(fields):
            a = aggs.get(f'a_{i}', {}).get('buckets', [])
            top = ','.join(str(b.get('key')) for b in a[:5])
            logger.info("DIAG terms field=%s buckets=%s top=%s", f, len(a), top)
    except Exception as e:
        logger.warning("Diagnostics failed: %s", e)

def purge_existing_objects():
    """Remove any conflicting saved objects by title to prevent stale scripted configs."""
    # Delete all index-patterns with title awswaf-*
    for ip_title in ['awswaf-*', 'awswaf']:
        find_ip = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_ip.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_ip.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': ip_title, 'per_page': 100})
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

    # Delete known Top 10 visualization IDs to ensure fresh publish
    vis_ids = [
        'top10ip', 'top10countries', 'top10webacl', 'top10hosts', 'top10uris', 'top10useragents', 'top10rules'
    ]
    for vid in vis_ids:
        try:
            del_v = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            del_v.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            requests.delete(del_v.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        except Exception:
            pass

    # Also delete any visualizations with "Top 10" in the title, if found
    try:
        find_v = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_v.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_v.add(query_params={'type': 'visualization', 'searchFields': 'title', 'search': 'Top 10', 'per_page': 100})
        rv = requests.get(find_v.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if rv.ok:
            for obj in rv.json().get('saved_objects', []):
                del_v2 = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                del_v2.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                requests.delete(del_v2.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    except Exception:
        pass

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
        # opensearch-py expects keyword-only args: name=, body=, params=
        # Use the actual template name from the dict key
        result = opensearch_client.indices.put_index_template(
            name=template,
            body=templates[template],
            params={'create': 'false', 'cause': 'Initial templates creation'}
        )
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
