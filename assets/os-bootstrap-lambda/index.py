import os
import json
import urllib3
import boto3
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import ReadOnlyCredentials

http = urllib3.PoolManager()


def _sign(method, url, body, region, service='es'):
    session = boto3.session.Session()
    creds = session.get_credentials().get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=body, headers={
        "Host": url.split("//")[1].split("/")[0],
        "Content-Type": "application/json",
    })
    SigV4Auth(ReadOnlyCredentials(creds.access_key, creds.secret_key, creds.token), service, region).add_auth(req)
    return dict(req.headers.items())


def _put(url, payload, region):
    body = json.dumps(payload).encode('utf-8')
    headers = _sign('PUT', url, body, region)
    r = http.request('PUT', url, body=body, headers=headers)
    if r.status >= 300:
        raise Exception(f"PUT {url} failed: {r.status} {r.data}")


def _get(url, region):
    headers = _sign('GET', url, None, region)
    r = http.request('GET', url, headers=headers)
    if r.status >= 300:
        raise Exception(f"GET {url} failed: {r.status} {r.data}")
    return json.loads(r.data.decode('utf-8'))


def _post(url, payload, region):
    body = json.dumps(payload).encode('utf-8')
    headers = _sign('POST', url, body, region)
    r = http.request('POST', url, body=body, headers=headers)
    if r.status >= 300:
        raise Exception(f"POST {url} failed: {r.status} {r.data}")
    return json.loads(r.data.decode('utf-8')) if r.data else {}


def _delete(url, region):
    headers = _sign('DELETE', url, None, region)
    r = http.request('DELETE', url, headers=headers)
    # tolerate 404
    if r.status >= 300 and r.status != 404:
        raise Exception(f"DELETE {url} failed: {r.status} {r.data}")


def _dashboards_request(method, base, path, region, payload=None):
    # Uses same SigV4 signing (service=es) but adds osd-xsrf header
    url = f"{base}/_dashboards{path}"
    body = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = _sign(method, url, body, region)
    headers['osd-xsrf'] = 'true'
    headers['Content-Type'] = 'application/json'
    r = http.request(method, url, body=body, headers=headers)
    if r.status >= 300:
        raise Exception(f"Dashboards {method} {url} failed: {r.status} {r.data}")
    return json.loads(r.data.decode('utf-8')) if r.data else {}


def _send_cfn_response(event, context, status, reason=None):
    response_url = event.get('ResponseURL')
    if not response_url:
        return
    body = {
        'Status': status,
        'Reason': reason or f"See details in CloudWatch Log Stream: {getattr(context, 'log_stream_name', 'N/A')}",
        'PhysicalResourceId': os.environ.get('PHYS_ID', 'osdfwIngestBootstrap'),
        'StackId': event.get('StackId'),
        'RequestId': event.get('RequestId'),
        'LogicalResourceId': event.get('LogicalResourceId'),
        'NoEcho': False,
        'Data': {}
    }
    data = json.dumps(body).encode('utf-8')
    http.request('PUT', response_url, body=data, headers={'content-type': '', 'content-length': str(len(data))})


def _apply_resources(endpoint, region):
    base = f"https://{endpoint}"
    # Optional full reset when debugging stale mappings
    if os.environ.get('FORCE_RESET', 'false').lower() == 'true':
        try:
            # delete indices first
            try:
                idxs = _get(base + "/_cat/indices/awswaf-*?format=json", region)
                for it in idxs:
                    name = it.get('index') or it.get('i')
                    if name:
                        _delete(base + f"/{name}", region)
            except Exception:
                pass
            # delete templates and pipeline
            _delete(base + "/_index_template/awswaf_template", region)
            _delete(base + "/_index_template/awswaf-logs", region)
            _delete(base + "/_ingest/pipeline/extract_true_client_ip", region)
        except Exception:
            pass
    # Ingest pipeline
    pipeline = {
        "description": "Extract client IP/country and normalize timestamp",
        "processors": [
            {
                "script": {
                    "lang": "painless",
                    "source": """
String xff = null;
if (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('headers')) {
  def headers = ctx.httpRequest.headers;
  if (headers instanceof List) {
    for (h in headers) {
      if (h != null && h.containsKey('name') && h.containsKey('value')) {
        String n = h.name == null ? "" : h.name.toString().toLowerCase();
        if (n == 'x-forwarded-for' || n == 'true-client-ip') { xff = h.value == null ? null : h.value.toString(); }
        if (n == 'host' && (ctx.host == null || ctx.host == '')) { ctx.host = h.value == null ? null : h.value.toString(); }
        if (n == 'user-agent' && (ctx.UserAgent == null || ctx.UserAgent == '')) { ctx.UserAgent = h.value == null ? null : h.value.toString(); }
      }
    }
  }
}
if (xff == null && ctx.containsKey('headers') && ctx.headers instanceof Map) {
  def hs = ctx.headers;
  if (hs.containsKey('x-forwarded-for') && hs['x-forwarded-for'] != null) { xff = hs['x-forwarded-for'].toString(); }
  else if (hs.containsKey('True-Client-IP') && hs['True-Client-IP'] != null) { xff = hs['True-Client-IP'].toString(); }
}
// Populate true_client_ip with robust fallbacks
if (xff != null) {
  int idx = xff.indexOf(',');
  String first = idx >= 0 ? xff.substring(0, idx).trim() : xff.trim();
  ctx.true_client_ip = first; ctx.true_client_ip_str = first;
} else if (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('clientIp') && ctx.httpRequest.clientIp != null) {
  ctx.true_client_ip = ctx.httpRequest.clientIp.toString();
  ctx.true_client_ip_str = ctx.true_client_ip;
} else if (ctx.containsKey('clientIp') && ctx.clientIp != null) {
  ctx.true_client_ip = ctx.clientIp.toString();
  ctx.true_client_ip_str = ctx.true_client_ip;
}
if (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('country') && ctx.httpRequest.country != null) { ctx.real_country_code = ctx.httpRequest.country.toString(); }
// Derive uri if present in httpRequest
if (ctx.containsKey('httpRequest') && ctx.httpRequest != null && ctx.httpRequest.containsKey('uri') && ctx.httpRequest.uri != null && (ctx.uri == null || ctx.uri == '')) {
  ctx.uri = ctx.httpRequest.uri.toString();
}
// Derive httpMethod/httpVersion into top-level fields
if (ctx.containsKey('httpRequest') && ctx.httpRequest != null) {
  if (ctx.httpRequest.containsKey('httpMethod') && ctx.httpRequest.httpMethod != null && (ctx.httpMethod == null || ctx.httpMethod == '')) {
    ctx.httpMethod = ctx.httpRequest.httpMethod.toString();
  }
  if (ctx.httpRequest.containsKey('httpVersion') && ctx.httpRequest.httpVersion != null && (ctx.httpVersion == null || ctx.httpVersion == '')) {
    ctx.httpVersion = ctx.httpRequest.httpVersion.toString();
  }
}
// Populate webacl/rule/rule_type from common WAF fields when missing
if ((ctx.webacl == null || ctx.webacl == '') && ctx.containsKey('webaclId') && ctx.webaclId != null) {
  ctx.webacl = ctx.webaclId.toString();
}
if ((ctx.rule == null || ctx.rule == '') && ctx.containsKey('terminatingRuleId') && ctx.terminatingRuleId != null) {
  ctx.rule = ctx.terminatingRuleId.toString();
}
if ((ctx.rule_type == null || ctx.rule_type == '') && ctx.containsKey('terminatingRuleType') && ctx.terminatingRuleType != null) {
  ctx.rule_type = ctx.terminatingRuleType.toString();
}
"""
                }
            },
            {
                "script": {
                    "lang": "painless",
                    "source": """
// Drop httpRequest.country to avoid dynamic object mapping conflicts; we already copied to real_country_code
if (ctx.containsKey('httpRequest') && ctx.httpRequest != null) {
  try { ctx.httpRequest.remove('country'); } catch (Exception e) { }
  // Also drop nested fields that previously caused type conflicts; they are copied to top-level
  try { ctx.httpRequest.remove('httpMethod'); } catch (Exception e) { }
  try { ctx.httpRequest.remove('httpVersion'); } catch (Exception e) { }
  try { ctx.httpRequest.remove('uri'); } catch (Exception e) { }
  try { ctx.httpRequest.remove('clientIp'); } catch (Exception e) { }
}
"""
                }
            },
            {
                "date": {
                    "field": "timestamp",
                    "formats": [
                        "strict_date_optional_time",
                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                        "epoch_millis"
                    ],
                    "timezone": "UTC",
                    "target_field": "timestamp",
                    "ignore_failure": False
                }
            }
        ]
    }
    _put(base + "/_ingest/pipeline/extract_true_client_ip", pipeline, region)

    # High-priority index template
    template = {
        "index_patterns": ["awswaf-*"] ,
        "priority": 3000,
        "template": {
            "settings": { "index.default_pipeline": "extract_true_client_ip" },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                    "true_client_ip_str": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "true_client_ip": {"type": "keyword", "ignore_above": 256},
                    "real_country_code": {"type": "keyword", "ignore_above": 256},
                    "webacl": {"type": "keyword", "ignore_above": 256},
                    "rule": {"type": "keyword", "ignore_above": 256},
                    "rule_type": {"type": "keyword", "ignore_above": 256},
                    "action": {"type": "keyword", "ignore_above": 256},
                    "host": {"type": "keyword", "ignore_above": 256},
                    "uri": {"type": "keyword", "ignore_above": 2048},
                    "httpMethod": {"type": "keyword", "ignore_above": 256},
                    "httpVersion": {"type": "keyword", "ignore_above": 256},
                    "UserAgent": {"type": "keyword", "ignore_above": 512},
                    "WebACL": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "Rule": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "RuleType": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    
                    "webaclname": {"type": "alias", "path": "webacl"},
                    "rulename": {"type": "alias", "path": "rule"}
                }
            }
        }
    }
    _put(base + "/_index_template/awswaf_template", template, region)

    # Create today's index proactively so template mappings apply before first write
    try:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        idx = f"awswaf-{today}"
        # If it doesn't exist, create it
        try:
            _get(base + f"/{idx}", region)
        except Exception:
            _put(base + f"/{idx}", {}, region)
    except Exception:
        pass

    # Ensure existing indices use the pipeline (dynamic setting) and have alias fields
    try:
        indices = _get(base + "/_cat/indices/awswaf-*?format=json", region)
        for item in indices:
            name = item.get('index') or item.get('i')
            if not name:
                continue
            settings_payload = {"index": {"default_pipeline": "extract_true_client_ip"}}
            _put(base + f"/{name}/_settings", settings_payload, region)
            # Add/update mappings with keyword subfields and legacy aliases
            mapping_payload = {
                "properties": {
                    "uri": {"type": "keyword", "ignore_above": 2048},
                    "true_client_ip": {"type": "keyword", "ignore_above": 256},
                    "real_country_code": {"type": "keyword", "ignore_above": 256},
                    "httpMethod": {"type": "keyword", "ignore_above": 256},
                    "httpVersion": {"type": "keyword", "ignore_above": 256},
                    "httpRequest.country.keyword": {"type": "alias", "path": "real_country_code"},
                    "httpRequest.clientIp.keyword": {"type": "alias", "path": "true_client_ip"},
                    "httpRequest.clientIp": {"type": "alias", "path": "true_client_ip"},
                    "httpRequest.uri.keyword": {"type": "alias", "path": "uri"},
                    "httpRequest.httpMethod.keyword": {"type": "alias", "path": "httpMethod"},
                    "httpRequest.httpVersion.keyword": {"type": "alias", "path": "httpVersion"},
                    "action.keyword": {"type": "alias", "path": "action"},
                    "webaclname": {"type": "alias", "path": "webacl"},
                    "rulename": {"type": "alias", "path": "rule"},
                    "webaclId.keyword": {"type": "alias", "path": "webacl"},
                    "terminatingRuleId.keyword": {"type": "alias", "path": "rule"}
                }
            }
            _put(base + f"/{name}/_mapping", mapping_payload, region)
    except Exception as e:
        # Non-fatal; continue even if listing fails
        pass

    # Reindex today's index if legacy mapping (pre-template) is detected
    try:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        idx = f"awswaf-{today}"
        # Check if index exists
        try:
            mapping = _get(base + f"/{idx}/_mapping", region)
        except Exception:
            mapping = None
        if mapping and idx in mapping:
            props = mapping[idx]['mappings'].get('properties', {})
            needs_reindex = False
            # If core fields missing or not keyword -> reindex
            for f in ['webacl', 'rule', 'real_country_code', 'httpMethod', 'httpVersion', 'uri']:
                t = props.get(f, {}).get('type')
                if f in ['httpMethod','httpVersion','uri']:
                    if t and t != 'keyword':
                        needs_reindex = True
                        break
                else:
                    if t != 'keyword':
                        needs_reindex = True
                        break
            # If legacy nested httpRequest mapping exists (object), force reindex
            http_req = props.get('httpRequest', {})
            if isinstance(http_req, dict) and 'properties' in http_req:
                # If it has country/httpMethod/httpVersion/uri inside -> reindex
                nested = http_req.get('properties', {})
                for nf in ['country','httpMethod','httpVersion','uri','clientIp']:
                    if nf in nested:
                        needs_reindex = True
                        break
            if needs_reindex:
                target = f"{idx}-v2"
                # Create target index (template applies automatically)
                _put(base + f"/{target}", {}, region)
                # Reindex and wait
                _post(base + "/_reindex?wait_for_completion=true", {
                    "source": {"index": idx},
                    "dest": {"index": target}
                }, region)
                # Point alias to target
                actions = {"actions": [
                    {"remove": {"index": idx, "alias": idx, "ignore_unavailable": True}},
                    {"add": {"index": target, "alias": idx}}
                ]}
                try:
                    _post(base + "/_aliases", actions, region)
                except Exception:
                    # If alias ops fail (name not alias), fallback: delete old and put alias
                    try:
                        _put(base + f"/{idx}/_close", {}, region)
                    except Exception:
                        pass
                    _put(base + f"/{idx}/_settings", {"index": {"routing.allocation.require._name": "_none_"}}, region)
                # Delete old index
                try:
                    headers = _sign('DELETE', base + f"/{idx}", None, region)
                    http.request('DELETE', base + f"/{idx}", headers=headers)
                except Exception:
                    pass
    except Exception:
        # Non-fatal; skip reindex failures to not block stack
        pass

    # Refresh Data View fields for awswaf-* to ensure saved objects resolve fields
    try:
        # find index-pattern id by title
        res = _dashboards_request('GET', base, '/api/saved_objects/_find?type=index-pattern&searchFields=title&search=awswaf-*', region)
        objs = res.get('saved_objects', [])
        if objs:
            idx_id = objs[0]['id']
            _dashboards_request('POST', base, f'/api/index_patterns/index_pattern/{idx_id}/refresh_fields', region)
    except Exception:
        # Non-fatal; dashboards API may not be available yet during domain boot
        pass


def handler(event, context):
    try:
        request_type = event.get('RequestType', 'Create')
        if request_type == 'Delete':
            _send_cfn_response(event, context, 'SUCCESS', 'No action on Delete')
            return {'status': 'deleted'}

        endpoint = os.environ['ES_ENDPOINT']
        region = os.environ['REGION']
        _apply_resources(endpoint, region)
        _send_cfn_response(event, context, 'SUCCESS')
        return {'status': 'ok'}
    except Exception as e:
        _send_cfn_response(event, context, 'FAILED', str(e))
        raise
