def ensure_country_field_alias():
    """Ensure a field alias exists: req_country_code -> real_country_code on awswaf-*.
    Safe to run repeatedly; adds alias if missing.
    """
    try:
        payload = {
            'properties': {
                'req_country_code': { 'type': 'alias', 'path': 'real_country_code' }
            }
        }
        opensearch_client.indices.put_mapping(index='awswaf-*', body=payload)
        logger.info('Ensured req_country_code alias to real_country_code')
    except Exception as e:
        logger.warning('Failed to ensure req_country_code alias: %s', e)
from __future__ import print_function

import json
import logging
import sys
import time

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
        # Wait for OpenSearch Dashboards to be responsive before proceeding
        wait_for_dashboards_ready(max_wait_seconds=180)
        # Hard cleanup of variant indices that cause mapping conflicts (e.g., awswaf-*-v2/v3)
        delete_variant_indices()
        import_index_templates(solution_components.templates)
        # Ensure ingest pipeline + template so req_* fields are indexed on ingest
        ensure_ingest_pipeline_and_template()
        # Create alias for backward-compat country field
        ensure_country_field_alias()
        # Header-only approach: no geoip. New docs will carry req_* via headers.
        # Keep a small backfill for recent docs where headers exist in _source
        backfill_req_fields_recent(days=7)
        # Run for all common tenants to ensure UI objects update wherever the user is viewing
        for tenant in ['global', '__user__', 'private']:
            service_settings.headers['securitytenant'] = tenant
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
                update_dashboard_control_panels()
                apply_console_equivalent_patches()
                hard_patch_country_saved_objects()
                brute_force_country_string_replace()
                overwrite_canonical_country_objects()
                bulk_overwrite_country_objects()
                import_overwrite_country_objects()
                delete_then_bulk_update_country_objects()
                force_put_country_objects_default()
                fix_dashboard_panel_titles()
            except Exception as e:
                logger.warning("Post-create cleanup encountered an issue (tenant=%s): %s", tenant, e)
            finally:
                # Always enforce country objects in default tenant
                try:
                    force_put_country_objects_default()
                except Exception as ee:
                    logger.warning("final enforce (create) failed: %s", ee)
        # Ensure the Data View picks up latest mappings automatically (per-tenant)
        for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
            if tenant is None:
                service_settings.headers.pop('securitytenant', None)
            else:
                service_settings.headers['securitytenant'] = tenant
            # Ensure XSRF headers required by older/newer Dashboards builds
            service_settings.headers['osd-xsrf'] = 'true'
            service_settings.headers['kbn-xsrf'] = 'true'
            service_settings.headers['kbn-version'] = '1.0.0'
            for t in ['awswaf', 'awswaf-*']:
                refresh_index_pattern_fields(t)
                # Fallback for environments without ingest permissions: add runtime fields so panels/filters work
                ensure_runtime_fields_on_index_pattern(t)
    except Exception as e:
        logger.error("Create flow encountered an error but will return SUCCESS: %s", e)

    # Ensure final enforcement for default tenant even if above loops completed without error
    try:
        logger.info('BEGIN final enforce (create) force_put_country_objects_default')
        force_put_country_objects_default()
    except Exception as e:
        logger.warning('final enforce (create-post) failed: %s', e)

    return "MyResourceId"


@helper.update
def update(event=None, context=None):
    logger.info("Got Update.")
    logger.debug("Sourcing additional settings from the event")

    # Support direct maintenance invoke when handler is lambda_function.update
    if isinstance(event, dict) and event.get('Action') == 'ForceCountryOverwrite':
        logger.info("Direct maintenance via update(): ForceCountryOverwrite (default tenant)")
        try:
            service_settings.source_settings_from_event(event or {})
        except Exception:
            pass
        try:
            # 1) Try force PUT/POST overwrite
            try:
                logger.info('ForceCountryOverwrite step: force_put_country_objects_default')
                force_put_country_objects_default()
            except Exception as e1:
                logger.warning('ForceCountryOverwrite step force_put failed: %s', e1)
            # 2) Last-resort delete+recreate
            try:
                logger.info('ForceCountryOverwrite step: force_recreate_country_objects_default')
                force_recreate_country_objects_default()
            except Exception as e2:
                logger.warning('ForceCountryOverwrite step force_recreate failed: %s', e2)
            # 3) Import NDJSON overwrite
            try:
                logger.info('ForceCountryOverwrite step: import_country_objects_default')
                import_country_objects_default()
            except Exception as e3:
                logger.warning('ForceCountryOverwrite step import failed: %s', e3)
            return {"status": "ok", "action": "ForceCountryOverwrite"}
        except Exception as e:
            logger.warning("ForceCountryOverwrite failed: %s", e)
            return {"status": "error", "action": "ForceCountryOverwrite", "error": str(e)}
    if isinstance(event, dict) and event.get('Action') == 'RefreshAndNormalize':
        logger.info("Direct maintenance via update(): recycle + normalize + refresh fields")
        try:
            service_settings.source_settings_from_event(event or {})
        except Exception:
            pass
        for tenant in ['global', '__user__', 'private']:
            service_settings.headers['securitytenant'] = tenant
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
        for tenant in ['global', '__user__', 'private']:
            service_settings.headers['securitytenant'] = tenant
            for t in ['awswaf', 'awswaf-*']:
                refresh_index_pattern_fields(t)
        # Final enforcement for default tenant even on direct-maintenance path
        try:
            force_put_country_objects_default()
        except Exception as e:
            logger.warning("final enforce (update-direct) failed: %s", e)
        return {"status": "ok"}

    try:
        service_settings.source_settings_from_event(event)
        # Ensure Dashboards is ready on update path as well
        wait_for_dashboards_ready(max_wait_seconds=180)
        # Cleanup variant indices before proceeding
        delete_variant_indices()
        # Ensure ingest pipeline/template present on update path too
        ensure_ingest_pipeline_and_template()
        # Ensure alias for legacy country field name
        ensure_country_field_alias()
        # Backfill recent docs to populate req_* if missing (from headers/httpRequest)
        backfill_req_fields_recent(days=7)
        for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
            if tenant is None:
                service_settings.headers.pop('securitytenant', None)
            else:
                service_settings.headers['securitytenant'] = tenant
            logger.info("Running update flow for tenant=%s", tenant)
            purge_existing_objects()
            recycle_dashboards_objects()
            try:
                remove_scripted_fields_from_index_pattern('awswaf-*')
                strip_scripts_from_saved_objects()
                enforce_terms_fields()
                set_legacy_maps_tile_url()
                normalize_fields_and_controls()
                update_all_controls_fields()
                update_dashboard_control_panels()
                apply_console_equivalent_patches()
                hard_patch_country_saved_objects()
                brute_force_country_string_replace()
                overwrite_canonical_country_objects()
                bulk_overwrite_country_objects()
                import_overwrite_country_objects()
                delete_then_bulk_update_country_objects()
                fix_dashboard_panel_titles()
            except Exception as e:
                logger.warning("Post-update cleanup encountered an issue (tenant=%s): %s", tenant, e)
            finally:
                try:
                    force_put_country_objects_default()
                except Exception as ee:
                    logger.warning("final enforce (update) failed: %s", ee)
        for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
            if tenant is None:
                service_settings.headers.pop('securitytenant', None)
            else:
                service_settings.headers['securitytenant'] = tenant
            # Ensure XSRF headers for all writes
            service_settings.headers['osd-xsrf'] = 'true'
            service_settings.headers['kbn-xsrf'] = 'true'
            service_settings.headers['kbn-version'] = '1.0.0'
            logger.info("Running maintenance flow for tenant=%s", tenant)
            for t in ['awswaf', 'awswaf-*']:
                refresh_index_pattern_fields(t)
                ensure_runtime_fields_on_index_pattern(t)
    except Exception as e:
        logger.error("Update flow encountered an error but will return SUCCESS: %s", e)
    # Ensure final enforcement for default tenant before returning
    try:
        logger.info('BEGIN final enforce (update) force_put_country_objects_default')
        force_put_country_objects_default()
    except Exception as e:
        logger.warning('final enforce (update-post) failed: %s', e)
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
        # Normalize event into dict if possible
        parsed = None
        if isinstance(event, dict):
            parsed = event
        else:
            try:
                parsed = json.loads(event) if event else {}
            except Exception:
                parsed = {}
        action = (parsed or {}).get('Action')
        logger.info('Handler received Action=%s', action)
        if isinstance(event, dict) and event.get('Action') == 'ForceCountryOverwrite':
            logger.info('Handler Action=ForceCountryOverwrite: enforcing default-tenant country objects now')
            try:
                service_settings.source_settings_from_event(event or {})
            except Exception:
                pass
            try:
                force_put_country_objects_default()
                logger.info('Handler Action=ForceCountryOverwrite: done')
                return {"status": "ok", "action": "ForceCountryOverwrite"}
            except Exception as e:
                logger.warning('Handler Action=ForceCountryOverwrite failed: %s', e)
                return {"status": "error", "action": "ForceCountryOverwrite", "error": str(e)}
        if action == 'ForceCountryOverwrite':
            logger.info('Handler(parsed) Action=ForceCountryOverwrite: enforcing default-tenant country objects now')
            try:
                service_settings.source_settings_from_event(parsed or {})
            except Exception:
                pass
            try:
                force_put_country_objects_default()
                logger.info('Handler(parsed) step force_put done')
                force_recreate_country_objects_default()
                logger.info('Handler(parsed) step force_recreate done')
                import_country_objects_default()
                logger.info('Handler(parsed) step import done')
                return {"status": "ok", "action": "ForceCountryOverwrite"}
            except Exception as e:
                logger.warning('Handler(parsed) Action=ForceCountryOverwrite failed: %s', e)
                return {"status": "error", "action": "ForceCountryOverwrite", "error": str(e)}
        if isinstance(event, dict) and event.get('Action') == 'RefreshAndNormalize':
            logger.info("Running direct maintenance: recycle + normalize + refresh fields")
            try:
                # Ensure service settings are initialized from env
                service_settings.source_settings_from_event(event or {})
            except Exception:
                pass
            # Do the same steps as in create/update
            # Ensure pipeline/template before normalization
            ensure_ingest_pipeline_and_template()
            # Ensure field alias so legacy references resolve
            ensure_country_field_alias()
            # cleanup variant indices before normalization
            delete_variant_indices()
            # Backfill recent docs to populate req_* if missing (from headers/httpRequest)
            backfill_req_fields_recent(days=7)
            for tenant in ['global', '__user__', 'private']:
                service_settings.headers['securitytenant'] = tenant
                logger.info("Direct maintenance via handler() for tenant=%s", tenant)
                purge_existing_objects()
                recycle_dashboards_objects()
                try:
                    remove_scripted_fields_from_index_pattern('awswaf-*')
                    strip_scripts_from_saved_objects()
                    enforce_terms_fields()
                    set_legacy_maps_tile_url()
                    normalize_fields_and_controls()
                    update_all_controls_fields()
                    update_dashboard_control_panels()
                    apply_console_equivalent_patches()
                    hard_patch_country_saved_objects()
                    brute_force_country_string_replace()
                    overwrite_canonical_country_objects()
                    bulk_overwrite_country_objects()
                    import_overwrite_country_objects()
                    delete_then_bulk_update_country_objects()
                    force_put_country_objects_default()
                    fix_dashboard_panels_and_visuals()
                    fix_dashboard_panel_titles()
                except Exception as e:
                    logger.warning("Direct maintenance cleanup encountered an issue (tenant=%s): %s", tenant, e)
                finally:
                    try:
                        force_put_country_objects_default()
                    except Exception as ee:
                        logger.warning("final enforce (handler) failed: %s", ee)
            for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
                if tenant is None:
                    service_settings.headers.pop('securitytenant', None)
                else:
                    service_settings.headers['securitytenant'] = tenant
                ensure_country_field_alias()
                for t in ['awswaf', 'awswaf-*']:
                    refresh_index_pattern_fields(t)
                    ensure_runtime_fields_on_index_pattern(t)
            return {"status": "ok"}
    except Exception as e:
        logger.warning("Direct maintenance path failed: %s", e)
    # Last-chance: enforce default-tenant overwrite before delegating to CFN helper
    try:
        logger.info('Handler last-chance enforce: step1 force_put_country_objects_default')
        force_put_country_objects_default()
    except Exception as e:
        logger.warning('Handler last-chance step1 failed: %s', e)
    try:
        logger.info('Handler last-chance enforce: step2 force_recreate_country_objects_default')
        force_recreate_country_objects_default()
    except Exception as e:
        logger.warning('Handler last-chance step2 failed: %s', e)
    try:
        logger.info('Handler last-chance enforce: step3 import_country_objects_default')
        import_country_objects_default()
    except Exception as e:
        logger.warning('Handler last-chance step3 failed: %s', e)
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

    # Ensure valid JSON payloads only; skip invalid to prevent 400s
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

    # Use a bounded timeout per request so we don't hang the whole invocation
    response = requests.request(method, f.url, auth=service_settings.aws_auth, headers=service_settings.headers, json=final_payload, timeout=15)

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


def wait_for_dashboards_ready(max_wait_seconds=180, interval_seconds=6):
    """
    Poll the Dashboards endpoint until it responds HTTP 200/ok or we time out.
    This prevents early calls during domain warmup from stalling the custom resource.
    """
    start = time.time()
    probe = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    # Use a lightweight endpoint; root should be enough to return 200/redirect
    probe.add(path=['_dashboards'])
    attempt = 0
    while time.time() - start < max_wait_seconds:
        attempt += 1
        try:
            r = requests.get(probe.url, auth=service_settings.aws_auth, headers=service_settings.headers, timeout=5)
            if r.ok:
                logger.info("Dashboards readiness OK on attempt %s (status=%s)", attempt, r.status_code)
                return
            logger.info("Dashboards probe attempt %s not ready (status=%s)", attempt, r.status_code)
        except Exception as e:
            logger.info("Dashboards probe attempt %s failed: %s", attempt, e)
        time.sleep(interval_seconds)
    logger.warning("Dashboards readiness timed out after %ss; proceeding anyway", max_wait_seconds)


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


def retitle_index_pattern(old_title, new_title):
    find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_url.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': old_title, 'per_page': 100})
    r = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        return
    results = r.json().get('saved_objects', [])
    if not results:
        return
    idx_id = results[0]['id']
    get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    get_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
    g = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not g.ok:
        return
    body = g.json()
    attrs = body.get('attributes', {})
    if attrs.get('title') == new_title:
        return
    put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    put_url.add(path=['_dashboards', 'api', 'saved_objects', 'index-pattern', idx_id])
    payload = {'attributes': {'title': new_title}}
    requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers, json=payload)

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
        'real_country_code': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String cc = null;"
                    "if (params._source != null) {\n"
                    "  if (params._source.containsKey('real_country_code') && params._source.real_country_code != null && params._source.real_country_code.toString().length() > 0) { cc = params._source.real_country_code.toString(); }\n"
                    "  else if (params._source.containsKey('req_country_code') && params._source.req_country_code != null && params._source.req_country_code.toString().length() > 0) { cc = params._source.req_country_code.toString(); }\n"
                    "}"
                    "if (cc == null && params._source != null && params._source.containsKey('httpRequest') && params._source.httpRequest != null && params._source.httpRequest.containsKey('headers')) {"
                    "  for (def h : params._source.httpRequest.headers) { if (h != null && h.name != null && h.value != null) { String n = h.name.toString(); if (n.equalsIgnoreCase('section-io-geo-country-code') || n.equalsIgnoreCase('CloudFront-Viewer-Country')) { cc = h.value.toString(); break; } } }"
                    "}"
                    "if (cc == null && params._source != null && params._source.containsKey('httpRequest') && params._source.httpRequest != null && params._source.httpRequest.containsKey('country')) { cc = params._source.httpRequest.country; }"
                    "if (cc != null) { emit(cc.toUpperCase()); } else { emit(null); }"
                )
            }
        },
        'req_country_code': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String cc = null;"
                    "for (def h : params._source.httpRequest.headers) { if (h.name != null && (h.name.equalsIgnoreCase('CloudFront-Viewer-Country') || h.name.equalsIgnoreCase('section-io-geo-country-code'))) { cc = h.value; break; } }"
                    "if (cc == null && params._source.containsKey('httpRequest') && params._source.httpRequest != null && params._source.httpRequest.containsKey('country')) { cc = params._source.httpRequest.country; }"
                    "emit(cc);"
                )
            }
        },
        'req_country_code_rt': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String cc = null;"
                    "// Prefer already-indexed canonical fields first\n"
                    "if (params._source != null) {\n"
                    "  if (params._source.containsKey('req_country_code') && params._source.req_country_code != null && params._source.req_country_code.toString().length() > 0) { cc = params._source.req_country_code.toString(); }\n"
                    "  else if (params._source.containsKey('real_country_code') && params._source.real_country_code != null && params._source.real_country_code.toString().length() > 0) { cc = params._source.real_country_code.toString(); }\n"
                    "}"
                    "if (params._source != null && params._source.containsKey('httpRequest') && params._source.httpRequest != null && params._source.httpRequest.containsKey('headers')) {"
                    "  if (cc == null) { for (def h : params._source.httpRequest.headers) { if (h != null && h.name != null && h.value != null) { String n = h.name.toString(); if (n.equalsIgnoreCase('section-io-geo-country-code') || n.equalsIgnoreCase('CloudFront-Viewer-Country')) { cc = h.value.toString(); break; } } } }"
                    "}"
                    "if (cc == null && params._source != null && params._source.containsKey('httpRequest') && params._source.httpRequest != null && params._source.httpRequest.containsKey('country')) { cc = params._source.httpRequest.country; }"
                    "if (cc != null) { emit(cc.toUpperCase()); } else { emit(null); }"
                )
            }
        },
        'req_asn': {
            'type': 'keyword',
            'script': {
                'source': (
                    "String asn = null;"
                    "for (def h : params._source.httpRequest.headers) { if (h.name != null && (h.name.equalsIgnoreCase('CloudFront-Viewer-ASN') || h.name.equalsIgnoreCase('section-io-geo-asn'))) { asn = h.value; break; } }"
                    "emit(asn);"
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
                    params = a.get('params', {}) if isinstance(a.get('params'), dict) else {}
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

                    # Ensure aggregations use keyword subfields for text fields
                    if a.get('type') == 'terms' and isinstance(params.get('field'), str):
                        if params['field'] in ['uri', 'host', 'UserAgent', 'rule']:
                            keyword_field = params['field'] + '.keyword'
                            if params['field'] != keyword_field:
                                params['field'] = keyword_field
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
        'top10countries': {'new_title': 'Top 20 Countries',    'field': 'real_country_code',  'size': 20, 'perPage': 20},
        'top10uris':      {'new_title': 'Top 20 URI',          'field': 'uri',                'size': 20, 'perPage': 20},
        'top10hosts':     {'new_title': 'Top 20 Hosts',        'field': 'host',               'size': 20, 'perPage': 20},
        'top10rules':     {'new_title': 'Top 20 Rules',        'field': 'rule',               'size': 20, 'perPage': 20},
        'top10webacl':    {'new_title': 'Top 20 ASN',          'field': 'req_asn',            'size': 20, 'perPage': 20},
    }
    for vid, cfg in id_targets.items():
        try:
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            rv = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not rv.ok:
                # If visualization is missing, create a minimal one so dashboard panels resolve by ID
                ensure_visualization_exists(vid, cfg.get('new_title') or vid, cfg.get('field'))
                rv = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
                if not rv.ok:
                    continue
            vfull = rv.json()
            vattrs = vfull.get('attributes', {})
            vis_state = json.loads(vattrs.get('visState', '{}'))
            changed = False
            if isinstance(vis_state.get('params'), dict) and vis_state.get('type') == 'table':
                if vis_state['params'].get('perPage') != cfg['perPage']:
                    vis_state['params']['perPage'] = cfg['perPage']
                    changed = True
            for a in vis_state.get('aggs', []) or []:
                if not isinstance(a, dict):
                    continue
                params = a.get('params', {}) if isinstance(a.get('params'), dict) else {}
                if a.get('type') == 'terms':
                    if params.get('size') != cfg['size']:
                        params['size'] = cfg['size']
                        a['params'] = params
                        changed = True
                f = params.get('field')
                # global field_map: always normalize to canonical, never revert
                fmap = {
                    'true_client_ip': 'req_true_client_ip',
                    'req_country_code': 'real_country_code',
                    'req_country_code_rt': 'real_country_code',
                    'httpRequest.clientIp': 'true_client_ip',
                    'httpRequest.clientIp.keyword': 'true_client_ip',
                    'httpRequest.country.keyword': 'real_country_code'
                }
                if f in fmap:
                    params['field'] = fmap[f]
                    a['params'] = params
                    changed = True
                # if the vid is one of our targets, enforce its canonical field
                if vid in targets and a.get('type') == 'terms':
                    tf = targets[vid]['field']
                    if params.get('field') != tf:
                        params['field'] = tf
                        a['params'] = params
                        changed = True
            # Standardize titles
            if isinstance(vis_state, dict) and isinstance(vis_state.get('title'), str) and vis_state['title'].startswith('Top 10 '):
                vis_state['title'] = 'Top 20 ' + vis_state['title'][7:]
                vattrs['title'] = vis_state['title']
                changed = True
            if vid in targets and vattrs.get('title') != targets[vid]['new_title']:
                vattrs['title'] = targets[vid]['new_title']
                if isinstance(vis_state, dict):
                    vis_state['title'] = targets[vid]['new_title']
                changed = True
            if changed:
                vattrs['visState'] = json.dumps(vis_state)
                sv = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                sv.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
                sv.add(query_params={'overwrite': 'true'})
                requests.post(sv.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              data=json.dumps({'attributes': vattrs, 'references': vfull.get('references', [])}))
        except Exception:
            continue
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

    # Generic visualization patcher
    find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_vis.add(query_params={'type': 'visualization', 'per_page': 1000})
    rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if rv.ok:
        for obj in rv.json().get('saved_objects', []):
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
            gv = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not gv.ok:
                continue
            body = gv.json()
            attrs = body.get('attributes', {})
            vis_state = attrs.get('visState')
            changed = False
            try:
                if isinstance(vis_state, str):
                    vs = json.loads(vis_state)
                else:
                    vs = vis_state or {}
                # Rewrite explicit terms fields if present
                if isinstance(vs, dict) and isinstance(vs.get('aggs'), list):
                    for a in vs['aggs']:
                        if isinstance(a, dict):
                            # Replace field param
                            p = a.get('params', {})
                            fname = p.get('field')
                            if fname in field_map:
                                p['field'] = field_map[fname]
                                changed = True
                            # Also scan schema params used by Lens tables
                            for k, v in list(p.items()):
                                if isinstance(v, str) and v in field_map:
                                    p[k] = field_map[v]
                                    changed = True
                if changed:
                    attrs['visState'] = json.dumps(vs)
                    put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                    put_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                    requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers, json={'attributes': attrs, 'references': body.get('references', [])})
            except Exception:
                pass

def find_index_pattern_id(title):
    """Return the saved object id of an index-pattern by title, or None."""
    find_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
    find_url.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
    find_url.add(query_params={'type': 'index-pattern', 'search_fields': 'title', 'search': title, 'per_page': 100})
    r = requests.get(find_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
    if not r.ok:
        return None
    results = r.json().get('saved_objects', [])
    return results[0]['id'] if results else None

def apply_console_equivalent_patches():
    """Replicate the browser console patch:
    - Refresh awswaf-* data view field caps by saved object id.
    - Rewrite any visualization that references req_country_code/req_country_code_rt
      in terms aggs or input_control_vis controls to real_country_code.
    """
    try:
        # 1) Refresh field caps for awswaf-* data view
        idx_id = find_index_pattern_id('awswaf-*')
        if idx_id:
            url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            url.add(path=['_dashboards', 'api', 'index_patterns', 'refresh_field_caps', idx_id])
            r = requests.post(url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not r.ok:
                logger.warning('Field caps refresh failed for %s: %s', idx_id, r.text)
        else:
            logger.warning('awswaf-* data view id not found for field caps refresh')

        # 2) Patch all visualizations
        find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_vis.add(query_params={'type': 'visualization', 'per_page': 1000})
        rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not rv.ok:
            return
        updated = 0
        for v in rv.json().get('saved_objects', []):
            attrs = v.get('attributes', {})
            vis_state_raw = attrs.get('visState')
            try:
                vs = json.loads(vis_state_raw) if isinstance(vis_state_raw, str) else (vis_state_raw or {})
            except Exception:
                continue
            changed = False
            # 2.a) terms agg fields
            if isinstance(vs.get('aggs'), list):
                for a in vs['aggs']:
                    if isinstance(a, dict) and a.get('type') == 'terms' and isinstance(a.get('params'), dict):
                        f = a['params'].get('field')
                        if f in ('req_country_code', 'req_country_code_rt'):
                            a['params']['field'] = 'real_country_code'
                            changed = True
            # 2.b) input controls
            if vs.get('type') == 'input_control_vis':
                params = vs.get('params') or {}
                ctrls = params.get('controls') or []
                for c in ctrls:
                    if not isinstance(c, dict):
                        continue
                    fname = c.get('fieldName') or c.get('field_name')
                    if fname in ('req_country_code', 'req_country_code_rt'):
                        c['fieldName'] = 'real_country_code'
                        changed = True
                if changed:
                    params['controls'] = ctrls
                    vs['params'] = params
            if not changed:
                continue
            attrs['visState'] = json.dumps(vs)
            put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            put_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', v['id']])
            put_url.add(query_params={'overwrite': 'true'})
            pr = requests.post(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                               data=json.dumps({'attributes': attrs, 'references': v.get('references', [])}))
            if pr.ok:
                updated += 1
            else:
                logger.warning('Failed to update visualization %s: %s', v['id'], pr.text)
        logger.info('Console-equivalent patches updated %s visualizations', updated)
    except Exception as e:
        logger.warning('apply_console_equivalent_patches failed: %s', e)

def hard_patch_country_saved_objects():
    """Force-overwrite specific saved objects by ID to use real_country_code.
    Targets:
    - filters (input_control_vis): change Country control fieldName to real_country_code
    - allcountries (region_map): change terms agg field to real_country_code
    - blockedcountries (region_map): change terms agg field to real_country_code
    - top10countries (table): change terms agg field to real_country_code
    """
    try:
        targets = ['filters', 'allcountries', 'blockedcountries', 'top10countries']
        for vid in targets:
            get_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            get_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            gv = requests.get(get_url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if not gv.ok:
                continue
            body = gv.json()
            attrs = body.get('attributes', {})
            vis_state_raw = attrs.get('visState')
            try:
                vs = json.loads(vis_state_raw) if isinstance(vis_state_raw, str) else (vis_state_raw or {})
            except Exception:
                continue
            changed = False
            # Patch terms aggs for known visualizations
            if isinstance(vs.get('aggs'), list):
                for a in vs['aggs']:
                    if isinstance(a, dict) and a.get('type') == 'terms' and isinstance(a.get('params'), dict):
                        # Force for our target IDs regardless of current field
                        if vid in ('allcountries', 'blockedcountries', 'top10countries'):
                            if a['params'].get('field') != 'real_country_code':
                                a['params']['field'] = 'real_country_code'
                                changed = True
                        elif a['params'].get('field') in ('req_country_code', 'req_country_code_rt'):
                            a['params']['field'] = 'real_country_code'
                            changed = True
            # Patch input controls for Filters
            if vs.get('type') == 'input_control_vis':
                params = vs.get('params') or {}
                ctrls = params.get('controls') or []
                for c in ctrls:
                    if not isinstance(c, dict):
                        continue
                    fname = c.get('fieldName') or c.get('field_name')
                    # Force Country control to real_country_code
                    if (fname in ('req_country_code', 'req_country_code_rt')) or (str(c.get('label', '')).lower() == 'country'):
                        if c.get('fieldName') != 'real_country_code':
                            c['fieldName'] = 'real_country_code'
                            changed = True
                if changed:
                    params['controls'] = ctrls
                    vs['params'] = params
            if not changed:
                continue
            attrs['visState'] = json.dumps(vs)
            save_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            save_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            # Prefer PUT for updates; POST overwrite can be flaky in some OS builds
            pr = requests.put(save_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                              json={'attributes': attrs, 'references': body.get('references', [])})
            if pr.ok:
                logger.info('Hard-patched visualization %s to real_country_code (status=%s)', vid, pr.status_code)
            else:
                logger.warning('Failed hard-patch for %s: status=%s body=%s', vid, pr.status_code, pr.text)

        # Also patch by title as extra safety in case IDs differ in tenant copies
        titles = ['Filters', 'Countries By Number of Request', 'Countries By Number of BLOCKED Request', 'Top 20 Countries', 'Top 10 Countries']
        find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_vis.add(query_params={'type': 'visualization', 'per_page': 1000})
        rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if rv.ok:
            for obj in rv.json().get('saved_objects', []):
                attrs = obj.get('attributes', {})
                title = str(attrs.get('title', ''))
                if title not in titles:
                    continue
                vis_state_raw = attrs.get('visState')
                try:
                    vs = json.loads(vis_state_raw) if isinstance(vis_state_raw, str) else (vis_state_raw or {})
                except Exception:
                    continue
                changed = False
                if vs.get('type') == 'input_control_vis':
                    params = vs.get('params') or {}
                    ctrls = params.get('controls') or []
                    for c in ctrls:
                        if not isinstance(c, dict):
                            continue
                        fname = c.get('fieldName') or c.get('field_name')
                        if (fname in ('req_country_code', 'req_country_code_rt')) or (str(c.get('label', '')).lower() == 'country'):
                            if c.get('fieldName') != 'real_country_code':
                                c['fieldName'] = 'real_country_code'
                                changed = True
                    if changed:
                        params['controls'] = ctrls
                        vs['params'] = params
                if isinstance(vs.get('aggs'), list):
                    for a in vs['aggs']:
                        if isinstance(a, dict) and a.get('type') == 'terms' and isinstance(a.get('params'), dict):
                            if a['params'].get('field') != 'real_country_code' and title.lower().startswith('countries by number') or title in ('Top 20 Countries', 'Top 10 Countries'):
                                a['params']['field'] = 'real_country_code'
                                changed = True
                if changed:
                    attrs['visState'] = json.dumps(vs)
                    put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                    put_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                    pr2 = requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                                       json={'attributes': attrs, 'references': obj.get('references', [])})
                    if pr2.ok:
                        logger.info('Hard-patched by title %s (id=%s) to real_country_code', title, obj['id'])
                    else:
                        logger.warning('Failed hard-patch by title %s (id=%s): %s', title, obj['id'], pr2.text)
    except Exception as e:
        logger.warning('hard_patch_country_saved_objects failed: %s', e)

def brute_force_country_string_replace():
    """As a last resort, perform a raw string replace inside visState for any visualization
    to convert req_country_code/req_country_code_rt to real_country_code. This circumvents
    any schema variations that prevented structured patching.
    """
    try:
        find_vis = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        find_vis.add(path=['_dashboards', 'api', 'saved_objects', '_find'])
        find_vis.add(query_params={'type': 'visualization', 'per_page': 1000})
        rv = requests.get(find_vis.url, auth=service_settings.aws_auth, headers=service_settings.headers)
        if not rv.ok:
            logger.warning('brute_force_country_string_replace list failed: %s', rv.text)
            return
        count = 0
        for obj in rv.json().get('saved_objects', []):
            attrs = obj.get('attributes', {})
            vs_raw = attrs.get('visState')
            if not isinstance(vs_raw, str):
                try:
                    vs_raw = json.dumps(vs_raw or {})
                except Exception:
                    continue
            new_raw = vs_raw.replace('"req_country_code"', '"real_country_code"').replace('"req_country_code_rt"', '"real_country_code"')
            if new_raw != vs_raw:
                attrs['visState'] = new_raw
                put_url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                put_url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', obj['id']])
                pr = requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                                   json={'attributes': attrs, 'references': obj.get('references', [])})
                if pr.ok:
                    count += 1
                else:
                    logger.warning('bruteforce update failed id=%s: %s', obj['id'], pr.text)
        logger.info('brute_force_country_string_replace updated %s visualizations', count)
    except Exception as e:
        logger.warning('brute_force_country_string_replace failed: %s', e)

def overwrite_canonical_country_objects():
    """Overwrite four target saved objects with canonical visState that uses real_country_code.
    IDs: filters, allcountries, blockedcountries, top10countries.
    """
    try:
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        # 1) Filters
        filters_vs = {
            'title': 'Filters',
            'type': 'input_control_vis',
            'params': {
                'controls': [
                    { 'fieldName': 'webacl', 'id': '1565169719620', 'indexPattern': 'awswaf', 'label': 'WebACL', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'rule', 'id': '1565169760470', 'indexPattern': 'awswaf', 'label': 'Rule', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'action', 'id': '1565169899571', 'indexPattern': 'awswaf', 'label': 'Action', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'real_country_code', 'id': '1565170498755', 'indexPattern': 'awswaf', 'label': 'Country', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'req_true_client_ip', 'id': '1565170536048', 'indexPattern': 'awswaf', 'label': 'Client IP', 'options': { 'dynamicOptions': True, 'multiselect': False, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'id': '1565182161719', 'indexPattern': 'awswaf', 'fieldName': 'host', 'parent': '', 'label': 'Host', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } },
                    { 'id': '1565775477773', 'indexPattern': 'awswaf', 'fieldName': 'rule_type', 'parent': '', 'label': 'Rule Type', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': False, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } }
                ],
                'pinFilters': True,
                'updateFiltersOnChange': True,
                'useTimeFilter': False
            },
            'aggs': []
        }
        put_saved_object('visualization', 'filters', {
            'title': 'Filters',
            'visState': json.dumps(filters_vs),
            'uiStateJSON': json.dumps({}),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '',
            'version': 1
        })

        # 2) Region maps
        def region_map(title):
            return {
                'title': title,
                'type': 'region_map',
                'params': {
                    'legendPosition': 'bottomright',
                    'addTooltip': True,
                    'colorSchema': 'Yellow to Red',
                    'selectedLayer': {
                        'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                        'created_at': '2017-04-26T17:12:15.978370',
                        'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                        'fields': [ { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' }, { 'type': 'id', 'name': 'iso3', 'description': 'ISO 3166-1 alpha-3 code' }, { 'type': 'property', 'name': 'name', 'description': 'name' } ],
                        'format': { 'type': 'geojson' }, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                    },
                    'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                    'selectedJoinField': { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' },
                    'isDisplayWarning': True,
                    'wms': { 'enabled': False, 'options': { 'format': 'image/png', 'transparent': True }, 'selectedTmsLayer': { 'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted' } },
                    'mapZoom': 2, 'mapCenter': [0, 0], 'outlineWeight': 1, 'showAllShapes': True
                },
                'aggs': [
                    { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} },
                    { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } }
                ]
            }
        put_saved_object('visualization', 'allcountries', {
            'title': 'Countries By Number of Request',
            'visState': json.dumps(region_map('Countries By Number of Request')),
            'uiStateJSON': json.dumps({}),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '',
            'version': 1
        })
        put_saved_object('visualization', 'blockedcountries', {
            'title': 'Countries By Number of BLOCKED Request',
            'visState': json.dumps(region_map('Countries By Number of BLOCKED Request')),
            'uiStateJSON': json.dumps({}),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps({ **search_source, 'query': { 'query': 'action: BLOCK', 'language': 'lucene' } }) },
            'description': '',
            'version': 1
        })

        # 3) Top 20 Countries (table)
        table_vs = {
            'title': 'Top 20 Countries', 'type': 'table',
            'params': { 'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'sort': { 'columnIndex': None, 'direction': None }, 'showTotal': False, 'totalFunc': 'sum' },
            'aggs': [
                { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} },
                { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } }
            ]
        }
        put_saved_object('visualization', 'top10countries', {
            'title': 'Top 20 Countries',
            'visState': json.dumps(table_vs),
            'uiStateJSON': json.dumps({ 'vis': { 'params': { 'sort': { 'columnIndex': None, 'direction': None } } } }),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '',
            'version': 1
        })
    except Exception as e:
        logger.warning('overwrite_canonical_country_objects failed: %s', e)

def put_saved_object(obj_type, obj_id, attributes):
    try:
        url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        url.add(path=['_dashboards', 'api', 'saved_objects', obj_type, obj_id])
        url.add(query_params={'overwrite': 'true'})
        r = requests.post(url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                          data=json.dumps({ 'attributes': attributes, 'references': [] }))
        if not r.ok:
            logger.warning('put_saved_object failed type=%s id=%s: %s', obj_type, obj_id, r.text)
        else:
            logger.info('put_saved_object updated type=%s id=%s', obj_type, obj_id)
    except Exception as e:
        logger.warning('put_saved_object exception type=%s id=%s: %s', obj_type, obj_id, e)

def bulk_overwrite_country_objects():
    """Use saved_objects _bulk_create with overwrite=true to atomically replace
    filters, allcountries, blockedcountries, top10countries with real_country_code.
    """
    try:
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        # Build payload
        def v(obj_type, obj_id, attrs):
            return { 'type': obj_type, 'id': obj_id, 'attributes': attrs, 'references': [] }

        # Filters attrs
        filters_attrs = {
            'title': 'Filters',
            'visState': json.dumps({
                'title': 'Filters', 'type': 'input_control_vis',
                'params': {
                    'controls': [
                        { 'fieldName': 'webacl', 'id': '1565169719620', 'indexPattern': 'awswaf', 'label': 'WebACL', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'rule', 'id': '1565169760470', 'indexPattern': 'awswaf', 'label': 'Rule', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'action', 'id': '1565169899571', 'indexPattern': 'awswaf', 'label': 'Action', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'real_country_code', 'id': '1565170498755', 'indexPattern': 'awswaf', 'label': 'Country', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'req_true_client_ip', 'id': '1565170536048', 'indexPattern': 'awswaf', 'label': 'Client IP', 'options': { 'dynamicOptions': True, 'multiselect': False, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'id': '1565182161719', 'indexPattern': 'awswaf', 'fieldName': 'host', 'parent': '', 'label': 'Host', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } },
                        { 'id': '1565775477773', 'indexPattern': 'awswaf', 'fieldName': 'rule_type', 'parent': '', 'label': 'Rule Type', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': False, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } }
                    ],
                    'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
                },
                'aggs': []
            }),
            'uiStateJSON': json.dumps({}),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '', 'version': 1
        }

        def region_map_attrs(title):
            return {
                'title': title,
                'visState': json.dumps({
                    'title': title,
                    'type': 'region_map',
                    'params': {
                        'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                        'selectedLayer': {
                            'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                            'created_at': '2017-04-26T17:12:15.978370',
                            'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                            'fields': [ { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' }, { 'type': 'id', 'name': 'iso3', 'description': 'ISO 3166-1 alpha-3 code' }, { 'type': 'property', 'name': 'name', 'description': 'name' } ],
                            'format': { 'type': 'geojson' }, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                        },
                        'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                        'selectedJoinField': { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' },
                        'isDisplayWarning': True,
                        'wms': { 'enabled': False, 'options': { 'format': 'image/png', 'transparent': True }, 'selectedTmsLayer': { 'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted' } },
                        'mapZoom': 2, 'mapCenter': [0, 0], 'outlineWeight': 1, 'showAllShapes': True
                    },
                    'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
                }),
                'uiStateJSON': json.dumps({}),
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
                'description': '', 'version': 1
            }

        top20countries_attrs = {
            'title': 'Top 20 Countries',
            'visState': json.dumps({
                'title': 'Top 20 Countries', 'type': 'table',
                'params': { 'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'sort': { 'columnIndex': None, 'direction': None }, 'showTotal': False, 'totalFunc': 'sum' },
                'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
            }),
            'uiStateJSON': json.dumps({ 'vis': { 'params': { 'sort': { 'columnIndex': None, 'direction': None } } } }),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '', 'version': 1
        }

        payload = [
            v('visualization', 'filters', filters_attrs),
            v('visualization', 'allcountries', region_map_attrs('Countries By Number of Request')),
            v('visualization', 'blockedcountries', region_map_attrs('Countries By Number of BLOCKED Request')),
            v('visualization', 'top10countries', top20countries_attrs)
        ]

        url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        url.add(path=['_dashboards', 'api', 'saved_objects', '_bulk_create'])
        url.add(query_params={'overwrite': 'true'})
        r = requests.post(url.url, auth=service_settings.aws_auth, headers=service_settings.headers, data=json.dumps(payload))
        if not r.ok:
            logger.warning('bulk_overwrite_country_objects failed: %s', r.text)
        else:
            logger.info('bulk_overwrite_country_objects applied.')
    except Exception as e:
        logger.warning('bulk_overwrite_country_objects exception: %s', e)

def import_overwrite_country_objects():
    """Authoritatively overwrite the 4 country objects using Saved Objects import API.
    This uses multipart/form-data with an NDJSON payload and overwrite=true.
    Targets: filters, allcountries, blockedcountries, top10countries.
    """
    try:
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        def nd(obj_type, obj_id, attrs):
            return json.dumps({ 'type': obj_type, 'id': obj_id, 'attributes': attrs, 'references': [] }) + "\n"

        # Build attributes mirroring canonical definitions
        filters_attrs = {
            'title': 'Filters',
            'visState': json.dumps({
                'title': 'Filters', 'type': 'input_control_vis',
                'params': {
                    'controls': [
                        { 'fieldName': 'webacl', 'id': '1565169719620', 'indexPattern': 'awswaf', 'label': 'WebACL', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'rule', 'id': '1565169760470', 'indexPattern': 'awswaf', 'label': 'Rule', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'action', 'id': '1565169899571', 'indexPattern': 'awswaf', 'label': 'Action', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'real_country_code', 'id': '1565170498755', 'indexPattern': 'awswaf', 'label': 'Country', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'fieldName': 'req_true_client_ip', 'id': '1565170536048', 'indexPattern': 'awswaf', 'label': 'Client IP', 'options': { 'dynamicOptions': True, 'multiselect': False, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                        { 'id': '1565182161719', 'indexPattern': 'awswaf', 'fieldName': 'host', 'parent': '', 'label': 'Host', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } },
                        { 'id': '1565775477773', 'indexPattern': 'awswaf', 'fieldName': 'rule_type', 'parent': '', 'label': 'Rule Type', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': False, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } }
                    ],
                    'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
                },
                'aggs': []
            }),
            'uiStateJSON': json.dumps({}),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '', 'version': 1
        }

        def region_map_attrs(title):
            return {
                'title': title,
                'visState': json.dumps({
                    'title': title,
                    'type': 'region_map',
                    'params': {
                        'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                        'selectedLayer': {
                            'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                            'created_at': '2017-04-26T17:12:15.978370',
                            'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                            'fields': [ { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' }, { 'type': 'id', 'name': 'iso3', 'description': 'ISO 3166-1 alpha-3 code' }, { 'type': 'property', 'name': 'name', 'description': 'name' } ],
                            'format': { 'type': 'geojson' }, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                        },
                        'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                        'selectedJoinField': { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' },
                        'isDisplayWarning': True,
                        'wms': { 'enabled': False, 'options': { 'format': 'image/png', 'transparent': True }, 'selectedTmsLayer': { 'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted' } },
                        'mapZoom': 2, 'mapCenter': [0, 0], 'outlineWeight': 1, 'showAllShapes': True
                    },
                    'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
                }),
                'uiStateJSON': json.dumps({}),
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
                'description': '', 'version': 1
            }

        top20countries_attrs = {
            'title': 'Top 20 Countries',
            'visState': json.dumps({
                'title': 'Top 20 Countries', 'type': 'table',
                'params': { 'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'sort': { 'columnIndex': None, 'direction': None }, 'showTotal': False, 'totalFunc': 'sum' },
                'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
            }),
            'uiStateJSON': json.dumps({ 'vis': { 'params': { 'sort': { 'columnIndex': None, 'direction': None } } } }),
            'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
            'description': '', 'version': 1
        }

        ndjson = (
            nd('visualization', 'filters', filters_attrs) +
            nd('visualization', 'allcountries', region_map_attrs('Countries By Number of Request')) +
            nd('visualization', 'blockedcountries', region_map_attrs('Countries By Number of BLOCKED Request')) +
            nd('visualization', 'top10countries', top20countries_attrs)
        )

        for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
            if tenant is None:
                service_settings.headers.pop('securitytenant', None)
            else:
                service_settings.headers['securitytenant'] = tenant

            url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            url.add(path=['_dashboards', 'api', 'saved_objects', '_import'])
            url.add(query_params={'overwrite': 'true'})

            files = {
                'file': ('objects.ndjson', ndjson, 'application/ndjson')
            }
            r = requests.post(url.url, auth=service_settings.aws_auth, headers={ **service_settings.headers, 'osd-xsrf': 'true' }, files=files)
            if not r.ok:
                logger.warning('import_overwrite_country_objects failed tenant=%s: %s', tenant or 'default', r.text)
                continue
            logger.info('import_overwrite_country_objects response tenant=%s: %s', tenant or 'default', r.text)

            # Verify: read back and ensure real_country_code present
            for vid in ['filters', 'allcountries', 'blockedcountries', 'top10countries']:
                gu = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                gu.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
                gr = requests.get(gu.url, auth=service_settings.aws_auth, headers=service_settings.headers)
                if not gr.ok:
                    logger.warning('verify GET %s tenant=%s failed: %s', vid, tenant or 'default', gr.text)
                    continue
                attrs = gr.json().get('attributes', {})
                vs = attrs.get('visState', '')
                has_real = 'real_country_code' in (vs or '')
                logger.info('verify %s tenant=%s real_country_code=%s', vid, tenant or 'default', has_real)
    except Exception as e:
        logger.warning('import_overwrite_country_objects exception: %s', e)

def delete_then_bulk_update_country_objects():
    """Final enforcement: delete the four objects then bulk-update them with canonical
    visState using real_country_code. Run for default tenant and global header.
    """
    try:
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        def region_map_vs(title):
            return {
                'title': title,
                'type': 'region_map',
                'params': {
                    'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                    'selectedLayer': {
                        'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                        'created_at': '2017-04-26T17:12:15.978370',
                        'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                        'fields': [ { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' }, { 'type': 'id', 'name': 'iso3', 'description': 'ISO 3166-1 alpha-3 code' }, { 'type': 'property', 'name': 'name', 'description': 'name' } ],
                        'format': { 'type': 'geojson' }, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                    },
                    'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                    'selectedJoinField': { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' },
                    'isDisplayWarning': True,
                    'wms': { 'enabled': False, 'options': { 'format': 'image/png', 'transparent': True }, 'selectedTmsLayer': { 'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted' } },
                    'mapZoom': 2, 'mapCenter': [0, 0], 'outlineWeight': 1, 'showAllShapes': True
                },
                'aggs': [
                    { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} },
                    { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } }
                ]
            }

        table_vs = {
            'title': 'Top 20 Countries', 'type': 'table',
            'params': { 'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'sort': { 'columnIndex': None, 'direction': None }, 'showTotal': False, 'totalFunc': 'sum' },
            'aggs': [
                { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} },
                { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } }
            ]
        }

        filters_vs = {
            'title': 'Filters', 'type': 'input_control_vis', 'params': {
                'controls': [
                    { 'fieldName': 'webacl', 'id': '1565169719620', 'indexPattern': 'awswaf', 'label': 'WebACL', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'rule', 'id': '1565169760470', 'indexPattern': 'awswaf', 'label': 'Rule', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'action', 'id': '1565169899571', 'indexPattern': 'awswaf', 'label': 'Action', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'real_country_code', 'id': '1565170498755', 'indexPattern': 'awswaf', 'label': 'Country', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'req_true_client_ip', 'id': '1565170536048', 'indexPattern': 'awswaf', 'label': 'Client IP', 'options': { 'dynamicOptions': True, 'multiselect': False, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'id': '1565182161719', 'indexPattern': 'awswaf', 'fieldName': 'host', 'parent': '', 'label': 'Host', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } },
                    { 'id': '1565775477773', 'indexPattern': 'awswaf', 'fieldName': 'rule_type', 'parent': '', 'label': 'Rule Type', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': False, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } }
                ],
                'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
            }, 'aggs': []
        }

        def attributes_for(vs):
            return {
                'title': vs.get('title', ''),
                'visState': json.dumps(vs),
                'uiStateJSON': json.dumps({}),
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
                'description': '', 'version': 1
            }

        for tenant in [None, 'global', 'Global', '__user__', 'private', 'Private']:
            if tenant is None:
                service_settings.headers.pop('securitytenant', None)
            else:
                service_settings.headers['securitytenant'] = tenant

            # Delete if exists
            for vid in ['filters', 'allcountries', 'blockedcountries', 'top10countries']:
                du = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                du.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
                try:
                    dr = requests.delete(du.url, auth=service_settings.aws_auth, headers={ **service_settings.headers, 'osd-xsrf': 'true' })
                    logger.info('delete %s tenant=%s status=%s', vid, tenant or 'default', getattr(dr, 'status_code', 'n/a'))
                except Exception:
                    pass

            # Bulk update with canonical content
            payload = [
                { 'type': 'visualization', 'id': 'filters', 'attributes': attributes_for(filters_vs) },
                { 'type': 'visualization', 'id': 'allcountries', 'attributes': attributes_for(region_map_vs('Countries By Number of Request')) },
                { 'type': 'visualization', 'id': 'blockedcountries', 'attributes': attributes_for(region_map_vs('Countries By Number of BLOCKED Request')) },
                { 'type': 'visualization', 'id': 'top10countries', 'attributes': attributes_for(table_vs) }
            ]
            bu = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            bu.add(path=['_dashboards', 'api', 'saved_objects', '_bulk_update'])
            rr = requests.post(bu.url, auth=service_settings.aws_auth, headers={ **service_settings.headers, 'Content-Type': 'application/json', 'osd-xsrf': 'true' }, data=json.dumps(payload))
            if not rr.ok:
                logger.warning('bulk_update failed tenant=%s: %s', tenant or 'default', rr.text)
            else:
                logger.info('bulk_update applied tenant=%s', tenant or 'default')

            # Verify
            for vid in ['filters', 'allcountries', 'blockedcountries', 'top10countries']:
                gu = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
                gu.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
                gr = requests.get(gu.url, auth=service_settings.aws_auth, headers=service_settings.headers)
                ok = False
                if gr.ok:
                    attrs = gr.json().get('attributes', {})
                    vs = attrs.get('visState', '')
                    ok = 'real_country_code' in (vs or '')
                logger.info('verify bulk_update %s tenant=%s real_country_code=%s', vid, tenant or 'default', ok)
    except Exception as e:
        logger.warning('delete_then_bulk_update_country_objects exception: %s', e)

def force_put_country_objects_default():
    """Final fallback: per-ID PUT in the default tenant only with strict headers.
    Ensures visState uses real_country_code. Verifies via GET.
    """
    try:
        logger.info('BEGIN force_put_country_objects_default')
        # Default tenant: ensure no tenant header
        service_settings.headers.pop('securitytenant', None)
        # Strict headers for Dashboards 1.0.0 (Kibana 7.10 lineage)
        service_settings.headers['osd-xsrf'] = 'true'
        service_settings.headers['kbn-xsrf'] = 'true'
        service_settings.headers['kbn-version'] = '7.10.2'
        service_settings.headers['osd-version'] = '1.0.0'
        service_settings.headers['Content-Type'] = 'application/json'

        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        def attributes_for_vs(vs):
            return {
                'title': vs.get('title', ''),
                'visState': json.dumps(vs),
                'uiStateJSON': json.dumps({}),
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) },
                'description': '', 'version': 1
            }

        # Canonical VS
        table_vs = {
            'title': 'Top 20 Countries', 'type': 'table',
            'params': { 'perPage': 20, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'sort': { 'columnIndex': None, 'direction': None }, 'showTotal': False, 'totalFunc': 'sum' },
            'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
        }

        def region_map_vs(title):
            return {
                'title': title,
                'type': 'region_map',
                'params': {
                    'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                    'selectedLayer': {
                        'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                        'created_at': '2017-04-26T17:12:15.978370',
                        'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                        'fields': [ { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' }, { 'type': 'id', 'name': 'iso3', 'description': 'ISO 3166-1 alpha-3 code' }, { 'type': 'property', 'name': 'name', 'description': 'name' } ],
                        'format': { 'type': 'geojson' }, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                    },
                    'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                    'selectedJoinField': { 'type': 'id', 'name': 'iso2', 'description': 'ISO 3166-1 alpha-2 code' },
                    'isDisplayWarning': True,
                    'wms': { 'enabled': False, 'options': { 'format': 'image/png', 'transparent': True }, 'selectedTmsLayer': { 'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted' } },
                    'mapZoom': 2, 'mapCenter': [0, 0], 'outlineWeight': 1, 'showAllShapes': True
                },
                'aggs': [ { 'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {} }, { 'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': { 'field': 'real_country_code', 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'otherBucketLabel': 'Other', 'missingBucket': False, 'missingBucketLabel': 'Missing', 'customLabel': 'Country' } } ]
            }

        filters_vs = {
            'title': 'Filters', 'type': 'input_control_vis', 'params': {
                'controls': [
                    { 'fieldName': 'webacl', 'id': '1565169719620', 'indexPattern': 'awswaf', 'label': 'WebACL', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'rule', 'id': '1565169760470', 'indexPattern': 'awswaf', 'label': 'Rule', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'action', 'id': '1565169899571', 'indexPattern': 'awswaf', 'label': 'Action', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'real_country_code', 'id': '1565170498755', 'indexPattern': 'awswaf', 'label': 'Country', 'options': { 'dynamicOptions': True, 'multiselect': True, 'order': 'desc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'fieldName': 'req_true_client_ip', 'id': '1565170536048', 'indexPattern': 'awswaf', 'label': 'Client IP', 'options': { 'dynamicOptions': True, 'multiselect': False, 'order': 'asc', 'size': 5, 'type': 'terms' }, 'parent': '', 'type': 'list' },
                    { 'id': '1565182161719', 'indexPattern': 'awswaf', 'fieldName': 'host', 'parent': '', 'label': 'Host', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } },
                    { 'id': '1565775477773', 'indexPattern': 'awswaf', 'fieldName': 'rule_type', 'parent': '', 'label': 'Rule Type', 'type': 'list', 'options': { 'type': 'terms', 'multiselect': False, 'dynamicOptions': True, 'size': 5, 'order': 'desc' } }
                ],
                'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
            }, 'aggs': []
        }

        payloads = [
            ('filters', attributes_for_vs(filters_vs)),
            ('allcountries', attributes_for_vs(region_map_vs('Countries By Number of Request'))),
            ('blockedcountries', attributes_for_vs(region_map_vs('Countries By Number of BLOCKED Request'))),
            ('top10countries', attributes_for_vs(table_vs)),
        ]

        for vid, attrs in payloads:
            url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            # Try PUT first (update), then POST overwrite if needed for compatibility
            put_url = furl(url)
            put_url.add(query_params={'overwrite': 'true'})
            payload = {'attributes': attrs, 'references': [], 'namespaces': ['default']}
            logger.info('force_put headers securitytenant=%s kbn-version=%s', service_settings.headers.get('securitytenant', 'default'), service_settings.headers.get('kbn-version'))
            r = requests.put(put_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                             json=payload)
            if not r.ok:
                logger.warning('force_put PUT failed id=%s status=%s body=%s', vid, r.status_code, r.text)
                post_url = furl(url)
                post_url.add(query_params={'overwrite': 'true'})
                r = requests.post(post_url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                                  json=payload)
                if not r.ok:
                    logger.warning('force_put POST failed id=%s status=%s body=%s', vid, r.status_code, r.text)
                else:
                    logger.info('force_put POST ok id=%s', vid)
            else:
                logger.info('force_put PUT ok id=%s', vid)
            # Verify
            gr = requests.get(url.url, auth=service_settings.aws_auth, headers=service_settings.headers)
            if gr.ok:
                vs = gr.json().get('attributes', {}).get('visState', '')
                logger.info('verify force_put %s real_country_code=%s', vid, ('real_country_code' in (vs or '')))
            else:
                logger.warning('verify force_put GET %s failed: %s', vid, gr.text)
    except Exception as e:
        logger.warning('force_put_country_objects_default exception: %s', e)


def force_recreate_country_objects_default():
    """Last resort: DELETE then POST the four visuals in default tenant with canonical payloads using real_country_code.
    """
    try:
        logger.info('BEGIN force_recreate_country_objects_default')
        service_settings.headers.pop('securitytenant', None)
        service_settings.headers['osd-xsrf'] = 'true'
        service_settings.headers['kbn-xsrf'] = 'true'
        service_settings.headers['kbn-version'] = '7.10.2'
        service_settings.headers['osd-version'] = '1.0.0'
        service_settings.headers['Content-Type'] = 'application/json'

        # Build canonical payloads (same as force_put builder)
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        def region_map_vs(title):
            return {
                'title': title,
                'type': 'region_map',
                'params': {
                    'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                    'selectedLayer': {
                        'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                        'created_at': '2017-04-26T17:12:15.978370',
                        'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                        'fields': [{'type':'id','name':'iso2','description':'ISO 3166-1 alpha-2 code'},{'type':'id','name':'iso3','description':'ISO 3166-1 alpha-3 code'},{'type':'property','name':'name','description':'name'}],
                        'format': {'type':'geojson'}, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                    },
                    'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                    'selectedJoinField': {'type':'id','name':'iso2','description':'ISO 3166-1 alpha-2 code'},
                    'isDisplayWarning': True,
                    'wms': {'enabled': False, 'options': {'format': 'image/png', 'transparent': True}, 'selectedTmsLayer': {'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted'}},
                    'mapZoom': 2, 'mapCenter': [0,0], 'outlineWeight': 1, 'showAllShapes': True
                },
                'aggs': [
                    {'id':'1','enabled':True,'type':'count','schema':'metric','params':{}},
                    {'id':'2','enabled':True,'type':'terms','schema':'segment','params':{'field':'real_country_code','size':20,'order':'desc','orderBy':'1','otherBucket':False,'otherBucketLabel':'Other','missingBucket':False,'missingBucketLabel':'Missing','customLabel':'Country'}}
                ]
            }

        table_vs = {
            'title': 'Top 20 Countries',
            'type': 'table',
            'params': {'perPage':20,'showPartialRows':False,'showMetricsAtAllLevels':False,'sort':{'columnIndex':None,'direction':None},'showTotal':False,'totalFunc':'sum'},
            'aggs': [
                {'id':'1','enabled':True,'type':'count','schema':'metric','params':{}},
                {'id':'2','enabled':True,'type':'terms','schema':'bucket','params':{'field':'real_country_code','size':20,'order':'desc','orderBy':'1','otherBucket':False,'otherBucketLabel':'Other','missingBucket':False,'missingBucketLabel':'Missing','customLabel':'Country'}}
            ]
        }

        filters_vs = {
            'title': 'Filters',
            'type': 'input_control_vis',
            'params': {
                'controls': [
                    {'fieldName':'webacl','id':'1565169719620','indexPattern':'awswaf','label':'WebACL','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'rule','id':'1565169760470','indexPattern':'awswaf','label':'Rule','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'action','id':'1565169899571','indexPattern':'awswaf','label':'Action','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'real_country_code','id':'1565170498755','indexPattern':'awswaf','label':'Country','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'req_true_client_ip','id':'1565170536048','indexPattern':'awswaf','label':'Client IP','options':{'dynamicOptions':True,'multiselect':False,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'id':'1565182161719','indexPattern':'awswaf','fieldName':'host','parent':'','label':'Host','type':'list','options':{'type':'terms','multiselect':True,'dynamicOptions':True,'size':5,'order':'desc'}},
                    {'id':'1565775477773','indexPattern':'awswaf','fieldName':'rule_type','parent':'','label':'Rule Type','type':'list','options':{'type':'terms','multiselect':False,'dynamicOptions':True,'size':5,'order':'desc'}}
                ],
                'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
            },
            'aggs': []
        }

        def attributes_for_vs(vs):
            return {
                'title': vs.get('title',''),
                'visState': json.dumps(vs),
                'uiStateJSON': '{}' if vs.get('type') != 'table' else json.dumps({'vis':{'params':{'sort':{'columnIndex':None,'direction':None}}}}),
                'description': '', 'version': 1,
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) }
            }

        payloads = [
            ('filters', attributes_for_vs(filters_vs)),
            ('allcountries', attributes_for_vs(region_map_vs('Countries By Number of Request'))),
            ('blockedcountries', attributes_for_vs(region_map_vs('Countries By Number of BLOCKED Request'))),
            ('top10countries', attributes_for_vs(table_vs)),
        ]

        for vid, attrs in payloads:
            base = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            base.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
            # Delete if exists
            try:
                d = requests.delete(base.url, auth=service_settings.aws_auth, headers=service_settings.headers, timeout=15)
                logger.info('force_recreate DELETE %s status=%s', vid, getattr(d,'status_code',None))
            except Exception as de:
                logger.warning('force_recreate DELETE %s error: %s', vid, de)
            # Recreate via POST overwrite
            post = furl(base)
            post.add(query_params={'overwrite':'true'})
            r = requests.post(post.url, auth=service_settings.aws_auth, headers=service_settings.headers, json={'attributes': attrs, 'references': []}, timeout=20)
            if not r.ok:
                logger.warning('force_recreate POST failed id=%s status=%s body=%s', vid, r.status_code, r.text)
            else:
                logger.info('force_recreate POST ok id=%s', vid)
            # Verify
            gr = requests.get(base.url, auth=service_settings.aws_auth, headers=service_settings.headers, timeout=10)
            ok = False
            if gr.ok:
                vs = gr.json().get('attributes', {}).get('visState', '')
                ok = ('real_country_code' in (vs or ''))
            logger.info('verify force_recreate %s real_country_code=%s', vid, ok)
    except Exception as e:
        logger.warning('force_recreate_country_objects_default exception: %s', e)

def import_country_objects_default():
    """Use saved_objects _import (NDJSON) to overwrite the four country visuals in default tenant."""
    try:
        logger.info('BEGIN import_country_objects_default')
        service_settings.headers.pop('securitytenant', None)
        # Import API needs xsrf/kbn/osd headers; requests will set multipart Content-Type
        base_headers = dict(service_settings.headers)
        base_headers['osd-xsrf'] = 'true'
        base_headers['kbn-xsrf'] = 'true'
        base_headers['kbn-version'] = '7.10.2'
        base_headers['osd-version'] = '1.0.0'

        idx_id = find_index_pattern_id('awswaf-*')
        search_source = { 'query': { 'query': '', 'language': 'lucene' }, 'filter': [] }
        if idx_id:
            search_source['index'] = idx_id

        def so_line(vid, attrs):
            return json.dumps({
                'type': 'visualization',
                'id': vid,
                'attributes': attrs,
                'references': []
            })

        def region_map_vs(title):
            return {
                'title': title,
                'type': 'region_map',
                'params': {
                    'legendPosition': 'bottomright', 'addTooltip': True, 'colorSchema': 'Yellow to Red',
                    'selectedLayer': {
                        'name': 'World Countries', 'origin': 'elastic_maps_service', 'id': 'world_countries',
                        'created_at': '2017-04-26T17:12:15.978370',
                        'attribution': '<a href="http://www.naturalearthdata.com/about/terms-of-use">Made with NaturalEarth</a> | <a href="https://www.elastic.co/elastic-maps-service">Elastic Maps Service</a>',
                        'fields': [{'type':'id','name':'iso2','description':'ISO 3166-1 alpha-2 code'},{'type':'id','name':'iso3','description':'ISO 3166-1 alpha-3 code'},{'type':'property','name':'name','description':'name'}],
                        'format': {'type':'geojson'}, 'layerId': 'elastic_maps_service.World Countries', 'isEMS': True
                    },
                    'emsHotLink': 'https://maps.elastic.co/v6.7?locale=en#file/world_countries',
                    'selectedJoinField': {'type':'id','name':'iso2','description':'ISO 3166-1 alpha-2 code'},
                    'isDisplayWarning': True,
                    'wms': {'enabled': False, 'options': {'format': 'image/png', 'transparent': True}, 'selectedTmsLayer': {'default': True, 'minZoom': 0, 'maxZoom': 10, 'attribution': '', 'id': 'TMS in config/kibana.yml', 'origin': 'self_hosted'}},
                    'mapZoom': 2, 'mapCenter': [0,0], 'outlineWeight': 1, 'showAllShapes': True
                },
                'aggs': [
                    {'id':'1','enabled':True,'type':'count','schema':'metric','params':{}},
                    {'id':'2','enabled':True,'type':'terms','schema':'segment','params':{'field':'real_country_code','size':20,'order':'desc','orderBy':'1','otherBucket':False,'otherBucketLabel':'Other','missingBucket':False,'missingBucketLabel':'Missing','customLabel':'Country'}}
                ]
            }

        table_vs = {
            'title': 'Top 20 Countries',
            'type': 'table',
            'params': {'perPage':20,'showPartialRows':False,'showMetricsAtAllLevels':False,'sort':{'columnIndex':None,'direction':None},'showTotal':False,'totalFunc':'sum'},
            'aggs': [
                {'id':'1','enabled':True,'type':'count','schema':'metric','params':{}},
                {'id':'2','enabled':True,'type':'terms','schema':'bucket','params':{'field':'real_country_code','size':20,'order':'desc','orderBy':'1','otherBucket':False,'otherBucketLabel':'Other','missingBucket':False,'missingBucketLabel':'Missing','customLabel':'Country'}}
            ]
        }

        filters_vs = {
            'title': 'Filters',
            'type': 'input_control_vis',
            'params': {
                'controls': [
                    {'fieldName':'webacl','id':'1565169719620','indexPattern':'awswaf','label':'WebACL','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'rule','id':'1565169760470','indexPattern':'awswaf','label':'Rule','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'action','id':'1565169899571','indexPattern':'awswaf','label':'Action','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'real_country_code','id':'1565170498755','indexPattern':'awswaf','label':'Country','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'fieldName':'req_true_client_ip','id':'1565170536048','indexPattern':'awswaf','label':'Client IP','options':{'dynamicOptions':True,'multiselect':False,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                    {'id':'1565182161719','indexPattern':'awswaf','fieldName':'host','parent':'','label':'Host','type':'list','options':{'type':'terms','multiselect':True,'dynamicOptions':True,'size':5,'order':'desc'}},
                    {'id':'1565775477773','indexPattern':'awswaf','fieldName':'rule_type','parent':'','label':'Rule Type','type':'list','options':{'type':'terms','multiselect':False,'dynamicOptions':True,'size':5,'order':'desc'}}
                ],
                'pinFilters': True, 'updateFiltersOnChange': True, 'useTimeFilter': False
            },
            'aggs': []
        }

        def attributes_for_vs(vs):
            return {
                'title': vs.get('title',''),
                'visState': json.dumps(vs),
                'uiStateJSON': '{}' if vs.get('type') != 'table' else json.dumps({'vis':{'params':{'sort':{'columnIndex':None,'direction':None}}}}),
                'description': '', 'version': 1,
                'kibanaSavedObjectMeta': { 'searchSourceJSON': json.dumps(search_source) }
            }

        lines = []
        lines.append(so_line('filters', attributes_for_vs(filters_vs)))
        lines.append(so_line('allcountries', attributes_for_vs(region_map_vs('Countries By Number of Request'))))
        lines.append(so_line('blockedcountries', attributes_for_vs(region_map_vs('Countries By Number of BLOCKED Request'))))
        lines.append(so_line('top10countries', attributes_for_vs(table_vs)))
        ndjson = ('\n'.join(lines) + '\n').encode('utf-8')

        url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        url.add(path=['_dashboards','api','saved_objects','_import'])
        url.add(query_params={'overwrite':'true'})
        files = {
            'file': ('objects.ndjson', ndjson, 'application/ndjson')
        }
        r = requests.post(url.url, auth=service_settings.aws_auth, headers=base_headers, files=files, timeout=30)
        if not r.ok:
            logger.warning('import_country_objects_default failed: %s %s', r.status_code, r.text)
        else:
            logger.info('import_country_objects_default ok')
        # Verify via GETs
        for vid in ['filters','allcountries','blockedcountries','top10countries']:
            gu = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
            gu.add(path=['_dashboards','api','saved_objects','visualization', vid])
            gr = requests.get(gu.url, auth=service_settings.aws_auth, headers=base_headers, timeout=10)
            ok = False
            if gr.ok:
                vs = gr.json().get('attributes', {}).get('visState', '')
                ok = ('real_country_code' in (vs or ''))
            logger.info('verify import %s real_country_code=%s', vid, ok)
    except Exception as e:
        logger.warning('import_country_objects_default exception: %s', e)

def ensure_visualization_exists(vid, title, field):
    """Create a minimal table visualization with terms agg for the given field if it does not already exist."""
    try:
        # Build visState and searchSourceJSON
        vis_state = {
            'title': title,
            'type': 'table',
            'params': {
                'perPage': 20,
                'showPartialRows': False,
                'showMetricsAtAllLevels': False,
                'sort': {'columnIndex': None, 'direction': None},
                'showTotal': False,
                'totalFunc': 'sum'
            },
            'aggs': [
                {'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}},
                {'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': {'field': field, 'size': 20, 'order': 'desc', 'orderBy': '1', 'otherBucket': False, 'missingBucket': False}}
            ]
        }
        idx_id = find_index_pattern_id('awswaf-*')
        search_source = {'query': {'query': '', 'language': 'lucene'}, 'filter': []}
        if idx_id:
            search_source['index'] = idx_id
        attributes = {
            'title': title,
            'visState': json.dumps(vis_state),
            'uiStateJSON': json.dumps({"vis": {"params": {"sort": {"columnIndex": None, "direction": None}}}}),
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps(search_source)}
        }
        url = furl(scheme="https", host=service_settings.host, port=service_settings.dashboards_port)
        url.add(path=['_dashboards', 'api', 'saved_objects', 'visualization', vid])
        url.add(query_params={'overwrite': 'true'})
        r = requests.post(url.url, auth=service_settings.aws_auth, headers=service_settings.headers,
                          data=json.dumps({'attributes': attributes, 'references': []}))
        if r.ok:
            logger.info("Created minimal visualization id=%s title=%s field=%s", vid, title, field)
        else:
            logger.warning("Failed to create visualization id=%s: %s", vid, r.text)
    except Exception as e:
        logger.warning("ensure_visualization_exists failed for %s: %s", vid, e)

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
        'top10countries': {'new_title': 'Top 20 Countries',    'field': 'real_country_code'},
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
                # create missing visualization with enforced field config
                if vid in targets:
                    ensure_visualization_exists(vid, targets[vid]['new_title'], targets[vid]['field'])
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
        'req_true_client_ip', 'real_country_code', 'req_asn',
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

def backfill_req_fields_recent(days=7):
    """In-place populate req_country_code, req_asn, req_true_client_ip for recent docs using update_by_query.
    Limits to the last N days to avoid long full reprocess. Safe to run multiple times.
    """
    try:
        script = (
            "def headers = (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('headers')) ? ctx.httpRequest.headers : null;"
            "def headerMap = new HashMap();"
            "if (headers != null) { for (def h : headers) { if (h != null && h.containsKey('name') && h.name != null && h.containsKey('value') && h.value != null) { headerMap.put(h.name.toLowerCase(), h.value); } } }"
            "if (ctx.req_country_code == null) { def cc = headerMap.get('cloudfront-viewer-country'); if (cc == null) { cc = headerMap.get('section-io-geo-country-code'); } if (cc == null && ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('country')) { cc = ctx.httpRequest.country; } if (cc != null) { ctx.req_country_code = cc; } }"
            "if (ctx.req_asn == null) { def asn = headerMap.get('cloudfront-viewer-asn'); if (asn == null) { asn = headerMap.get('section-io-geo-asn'); } if (asn != null) { ctx.req_asn = asn; } }"
            "if (ctx.req_true_client_ip == null) { def tci = headerMap.get('true-client-ip'); if (tci == null) { def xff = headerMap.get('x-forwarded-for'); if (xff != null) { int idx = xff.indexOf(','); tci = (idx > 0) ? xff.substring(0, idx).trim() : xff.trim(); } } if (tci == null && ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('clientIp')) { tci = ctx.httpRequest.clientIp; } if (tci != null) { ctx.req_true_client_ip = tci; } }"
        )
        def make_body(range_clause=None):
            q = {
                'bool': {
                    'should': [
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_country_code' } } } },
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_asn' } } } },
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_true_client_ip' } } } }
                    ],
                    'minimum_should_match': 1
                }
            }
            if range_clause:
                q['bool'].setdefault('must', []).append(range_clause)
            return {
                'script': { 'lang': 'painless', 'source': script },
                'query': q
            }

        body = make_body({ 'range': { 'timestamp': { 'gte': f"now-{days}d" } } })
        res = opensearch_client.update_by_query(index='awswaf-*', body=body, refresh=True, conflicts='proceed', slices='auto', wait_for_completion=True)
        logger.info("Backfill update_by_query took=%s updated=%s version_conflicts=%s", res.get('took'), res.get('updated'), res.get('version_conflicts'))
        updated = res.get('updated') if isinstance(res, dict) else None
        # Phase 2: if nothing updated, try broader 180d window
        if not updated:
            body2 = make_body({ 'range': { 'timestamp': { 'gte': 'now-180d' } } })
            res2 = opensearch_client.update_by_query(index='awswaf-*', body=body2, refresh=True, conflicts='proceed', slices='auto', wait_for_completion=True)
            logger.info("Backfill(180d) took=%s updated=%s version_conflicts=%s", res2.get('took'), res2.get('updated'), res2.get('version_conflicts'))
            updated2 = res2.get('updated') if isinstance(res2, dict) else None
            # Phase 3: final fallback without time filter
            if not updated2:
                body3 = make_body(None)
                res3 = opensearch_client.update_by_query(index='awswaf-*', body=body3, refresh=True, conflicts='proceed', slices='auto', wait_for_completion=True)
                logger.info("Backfill(all) took=%s updated=%s version_conflicts=%s", res3.get('took'), res3.get('updated'), res3.get('version_conflicts'))
    except Exception as e:
        logger.warning("Backfill update_by_query failed or not permitted: %s", e)

def delete_variant_indices():
    """Delete experimental/reindexed variant indices like awswaf-*-v2/v3 that cause mapping conflicts.
    We list with cat indices to avoid deleting unintended patterns, then delete exact names.
    """
    try:
        indices = opensearch_client.cat.indices(index='awswaf-*-v*', format='json')
        if isinstance(indices, list):
            for entry in indices:
                name = entry.get('index') or entry.get('i')
                if isinstance(name, str) and name.startswith('awswaf-') and '-v' in name:
                    try:
                        opensearch_client.indices.delete(index=name, ignore=[404])
                        logger.info("Deleted variant index %s", name)
                    except Exception as de:
                        logger.warning("Failed to delete variant index %s: %s", name, de)
    except Exception as e:
        logger.info("No variant indices to delete or cat indices not permitted: %s", e)

def reindex_recent_days_through_pipeline(days=2):
    """For the last N calendar days, reindex each awswaf-YYYY-MM-DD into -v2 with the ingest pipeline,
    then delete the original index to avoid duplicates. This immediately populates geo-derived country.
    Safe to run multiple times: skips if target exists with same or higher doc count.
    """
    try:
        # Find available daily indices
        indices_info = opensearch_client.cat.indices(index='awswaf-*', format='json')
        if not isinstance(indices_info, list):
            return
        import datetime as _dt
        today = _dt.datetime.utcnow().date()
        candidates = []
        for d in range(days):
            day = today - _dt.timedelta(days=d)
            candidates.append(f"awswaf-{day.isoformat()}")
        for base in candidates:
            if not any(ent.get('index') == base for ent in indices_info):
                continue
            v2 = base + '-v2'
            # If v2 exists, compare counts
            base_count = opensearch_client.count(index=base).get('count', 0)
            v2_exists = False
            try:
                v2_count = opensearch_client.count(index=v2).get('count', 0)
                v2_exists = True
            except Exception:
                v2_count = 0
            if v2_exists and v2_count >= base_count and base_count > 0:
                # Already processed
                continue
            # Create v2 by reindexing through pipeline
            body = { 'source': { 'index': base }, 'dest': { 'index': v2, 'pipeline': 'awswaf_req_fields_v1' } }
            opensearch_client.reindex(body=body, wait_for_completion=True, refresh=True)
            # Validate
            v2_count_after = opensearch_client.count(index=v2).get('count', 0)
            if v2_count_after >= base_count:
                # Delete original to avoid duplicates; data view awswaf-* will include v2
                try:
                    opensearch_client.indices.delete(index=base)
                except Exception as de:
                    logger.warning('Failed to delete original index %s after reindex: %s', base, de)
    except Exception as e:
        logger.warning('Reindex recent days through pipeline failed: %s', e)

def reindex_force_today_to_v3():
    """Force reindex of today's awswaf-YYYY-MM-DD into -v3 via pipeline and delete base/-v2 if v3 count >= base.
    """
    try:
        import datetime as _dt
        today = _dt.datetime.utcnow().date()
        base = f"awswaf-{today.isoformat()}"
        v2 = base + '-v2'
        v3 = base + '-v3'
        # If base doesn't exist, nothing to do
        try:
            base_count = opensearch_client.count(index=base).get('count', 0)
        except Exception:
            return
        if base_count == 0:
            return
        # Reindex to v3 through pipeline
        body = { 'source': { 'index': base }, 'dest': { 'index': v3, 'pipeline': 'awswaf_req_fields_v1' } }
        opensearch_client.reindex(body=body, wait_for_completion=True, refresh=True)
        v3_count = 0
        try:
            v3_count = opensearch_client.count(index=v3).get('count', 0)
        except Exception:
            v3_count = 0
        if v3_count >= base_count:
            # Delete older generations
            try:
                opensearch_client.indices.delete(index=base)
            except Exception as de:
                logger.warning('Failed deleting %s: %s', base, de)
            try:
                opensearch_client.indices.delete(index=v2)
            except Exception:
                pass
    except Exception as e:
        logger.warning('reindex_force_today_to_v3 failed: %s', e)

def apply_pipeline_via_update_by_query(days=30):
    """Apply the ingest pipeline to existing documents in-place using update_by_query with pipeline param.
    This triggers geoip enrichment to fill req_country_code when missing. Limited to last N days.
    """
    try:
        pipeline_id = 'awswaf_req_fields_v1'
        body = {
            'query': {
                'bool': {
                    'must': [ { 'range': { 'timestamp': { 'gte': f"now-{days}d" } } } ],
                    'should': [
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_country_code' } } } },
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_asn' } } } },
                        { 'bool': { 'must_not': { 'exists': { 'field': 'req_true_client_ip' } } } }
                    ],
                    'minimum_should_match': 1
                }
            }
        }
        res = opensearch_client.update_by_query(index='awswaf-*', body=body, refresh=True, conflicts='proceed', slices='auto', wait_for_completion=True, params={'pipeline': pipeline_id})
        logger.info('apply_pipeline_via_update_by_query updated=%s took=%s', res.get('updated'), res.get('took'))
    except Exception as e:
        logger.warning('apply_pipeline_via_update_by_query failed: %s', e)

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

def ensure_ingest_pipeline_and_template():
    """Create/overwrite an ingest pipeline to extract req_* fields from headers and
    attach it via index template and index settings for awswaf-* indices.
    """
    pipeline_id = 'awswaf_req_fields_v1'
    template_name = 'awswaf_template_req_fields'
    try:
        # 1) Put ingest pipeline
        script = {
            'description': 'Extract req_* fields from httpRequest and headers, derive country via geoip when missing',
            'processors': [
                { 'script': {
                    'lang': 'painless',
                    'source': (
                        "def headers = (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('headers')) ? ctx.httpRequest.headers : null;"
                        "def headerMap = new HashMap();"
                        "if (headers != null) { for (def h : headers) { if (h != null && h.containsKey('name') && h.name != null && h.containsKey('value') && h.value != null) { headerMap.put(h.name.toLowerCase(), h.value); } } }"
                        "def asn = headerMap.get('cloudfront-viewer-asn'); if (asn == null) { asn = headerMap.get('section-io-geo-asn'); } if (asn != null) { ctx.req_asn = asn; }"
                        "def cc = headerMap.get('cloudfront-viewer-country'); if (cc == null) { cc = headerMap.get('section-io-geo-country-code'); } if (cc == null && ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('country')) { cc = ctx.httpRequest.country; } if (cc != null) { ctx.req_country_code = cc; }"
                        "def tci = headerMap.get('true-client-ip'); if (tci == null) { def xff = headerMap.get('x-forwarded-for'); if (xff != null) { int idx = xff.indexOf(','); tci = (idx > 0) ? xff.substring(0, idx).trim() : xff.trim(); } } if (tci == null && ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('clientIp')) { tci = ctx.httpRequest.clientIp; } if (tci != null) { ctx.req_true_client_ip = tci; }"
                    )
                }},
                { 'geoip': { 'field': 'req_true_client_ip', 'target_field': 'req_geoip', 'ignore_missing': True }, 'ignore_failure': True },
                { 'script': {
                    'lang': 'painless',
                    'source': (
                        "if (ctx.req_country_code == null && ctx.containsKey('req_geoip') && ctx.req_geoip != null && ctx.req_geoip.containsKey('country_iso_code')) { ctx.req_country_code = ctx.req_geoip.country_iso_code; }"
                    )
                }},
                { 'remove': { 'field': 'req_geoip', 'ignore_missing': True } }
            ]
        }
        opensearch_client.ingest.put_pipeline(id=pipeline_id, body=script)
        logger.info('Put ingest pipeline %s', pipeline_id)
        # Verify pipeline includes geoip; if not, retry once
        try:
            p = opensearch_client.ingest.get_pipeline(id=pipeline_id)
            has_geoip = False
            if isinstance(p, dict):
                proc = ((p.get(pipeline_id) or {}).get('processors')) or []
                for step in proc:
                    if isinstance(step, dict) and 'geoip' in step:
                        has_geoip = True
                        break
            if not has_geoip:
                opensearch_client.ingest.put_pipeline(id=pipeline_id, body=script)
                logger.info('Re-put pipeline %s to ensure geoip present', pipeline_id)
        except Exception as pe:
            logger.warning('Pipeline verification failed: %s', pe)

        # 2) Put index template for awswaf-* with mappings and default_pipeline
        template_body = {
            'index_patterns': ['awswaf-*'],
            'template': {
                'settings': {
                    'index': {
                        'default_pipeline': pipeline_id
                    }
                },
                'mappings': {
                    'dynamic': True,
                    'properties': {
                        'req_true_client_ip': {'type': 'keyword'},
                        'req_country_code':   {'type': 'keyword'},
                        'req_asn':            {'type': 'keyword'}
                    }
                }
            },
            'priority': 500
        }
        opensearch_client.indices.put_index_template(name=template_name, body=template_body, params={'create': 'false'})
        logger.info('Put index template %s for awswaf-*', template_name)

        # 3) For existing indices, set default_pipeline now so new docs get processed
        try:
            existing = opensearch_client.indices.get(index='awswaf-*')
            for idx in existing.keys():
                try:
                    opensearch_client.indices.put_settings(index=idx, body={'index': {'default_pipeline': pipeline_id}})
                    logger.info('Set default_pipeline=%s on %s', pipeline_id, idx)
                except Exception as ie:
                    logger.warning('Failed to set default_pipeline on %s: %s', idx, ie)
            # Cleanup any reindexed variant indices that may introduce mapping conflicts
            try:
                variants = opensearch_client.indices.get(index='awswaf-*-v*')
                for v in variants.keys():
                    try:
                        opensearch_client.indices.delete(index=v)
                        logger.info('Deleted reindexed variant %s to avoid mapping conflicts', v)
                    except Exception as de:
                        logger.warning('Failed to delete variant %s: %s', v, de)
            except Exception:
                pass
        except Exception as e:
            logger.warning('Listing existing awswaf-* indices failed or none present: %s', e)
    except Exception as e:
        logger.warning('ensure_ingest_pipeline_and_template failed: %s', e)


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
