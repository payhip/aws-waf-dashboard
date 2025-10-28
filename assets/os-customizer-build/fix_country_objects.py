#!/usr/bin/env python3
"""
Direct maintenance script to fix country visualizations in OpenSearch Dashboards.
This bypasses the CloudFormation helper and directly overwrites the saved objects.
"""
import json
import random
import os
import logging
import boto3
import urllib.request
import urllib.parse
import urllib.error
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get environment variables
ES_ENDPOINT = os.environ.get('ES_ENDPOINT', 'search-osdfw-opensearch-domain-o4qqwqklqckzntadqra5u77axa.us-east-1.es.amazonaws.com')
REGION = os.environ.get('REGION', 'us-east-1')

def get_aws_auth():
    """Get AWS SigV4Auth for OpenSearch API calls."""
    session = boto3.Session()
    credentials = session.get_credentials()
    return SigV4Auth(credentials, 'es', REGION)

def make_signed_request(method, url, headers=None, data=None, params=None):
    """Make a signed request to OpenSearch."""
    if headers is None:
        headers = {}
    if params:
        url_parts = list(urllib.parse.urlparse(url))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urllib.parse.urlencode(query)
        url = urllib.parse.urlunparse(url_parts)
    
    request = AWSRequest(method=method, url=url, data=data, headers=headers)
    auth = get_aws_auth()
    auth.add_auth(request)
    
    try:
        if method == 'GET':
            req = urllib.request.Request(url, headers=dict(request.headers))
            response = urllib.request.urlopen(req)
        else:  # POST, PUT, DELETE
            req = urllib.request.Request(url, data=data, headers=dict(request.headers), method=method)
            response = urllib.request.urlopen(req)
        
        response_body = response.read().decode('utf-8')
        status_code = response.getcode()
        return status_code, response_body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')

def find_index_pattern_id(pattern_title):
    """Find the ID of an index pattern by title."""
    url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/_find"
    headers = {
        'osd-xsrf': 'true',
        'kbn-xsrf': 'true',
        'kbn-version': '7.10.2',
        'osd-version': '1.0.0',
        'Content-Type': 'application/json'
    }
    params = {
        'type': 'index-pattern',
        'search_fields': 'title',
        'search': pattern_title
    }
    
    status_code, response_body = make_signed_request('GET', url, headers=headers, params=params)
    
    if status_code != 200:
        logger.warning(f"Failed to find index pattern {pattern_title}: {status_code} {response_body}")
        return None
    
    data = json.loads(response_body)
    for hit in data.get('saved_objects', []):
        if hit.get('attributes', {}).get('title') == pattern_title:
            return hit.get('id')
    return None

def import_country_objects():
    """Overwrite the four country visuals and return verification results per id."""
    logger.info('BEGIN import_country_objects')
    
    # Headers for all requests
    headers = {
        'osd-xsrf': 'true',
        'kbn-xsrf': 'true',
        'kbn-version': '7.10.2',
        'osd-version': '1.0.0',
        'Content-Type': 'application/json'
    }
    
    # Find index pattern ID
    idx_id = find_index_pattern_id('awswaf-*')
    search_source = {'query': {'query': '', 'language': 'lucene'}, 'filter': []}
    if idx_id:
        search_source['index'] = idx_id
    
    # Build canonical visualizations with real_country_code
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

    asn_vs = {
        'title': 'Top 20 ASN',
        'type': 'table',
        'params': {'perPage':20,'showPartialRows':False,'showMetricsAtAllLevels':False,'sort':{'columnIndex':None,'direction':None},'showTotal':False,'totalFunc':'sum'},
        'aggs': [
            {'id':'1','enabled':True,'type':'count','schema':'metric','params':{}},
            {'id':'2','enabled':True,'type':'terms','schema':'bucket','params':{'field':'req_asn','size':100,'order':'desc','orderBy':'1','otherBucket':False,'otherBucketLabel':'Other','missingBucket':False,'missingBucketLabel':'Missing','customLabel':'ASN'}}
        ]
    }
    
    # Use actual index pattern id for input controls (avoids "Control has not been initialized")
    filter_index = idx_id if idx_id else 'awswaf'
    filters_vs = {
        'title': 'Filters',
        'type': 'input_control_vis',
        'params': {
            'controls': [
                {'id':'ctrl_webacl','fieldName':'webacl','indexPattern':filter_index,'label':'WebACL','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                {'id':'ctrl_rule','fieldName':'rule','indexPattern':filter_index,'label':'Rule','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                {'id':'ctrl_action','fieldName':'action','indexPattern':filter_index,'label':'Action','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                {'id':'ctrl_country','fieldName':'real_country_code','indexPattern':filter_index,'label':'Country','options':{'dynamicOptions':True,'multiselect':True,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                {'id':'ctrl_client_ip','fieldName':'req_true_client_ip','indexPattern':filter_index,'label':'Client IP','options':{'dynamicOptions':True,'multiselect':False,'order':'desc','size':5,'type':'terms'},'parent':'','type':'list'},
                {'id':'ctrl_host','indexPattern':filter_index,'fieldName':'host','parent':'','label':'Host','type':'list','options':{'type':'terms','multiselect':True,'dynamicOptions':True,'size':5,'order':'desc'}},
                {'id':'ctrl_rule_type','indexPattern':filter_index,'fieldName':'rule_type','parent':'','label':'Rule Type','type':'list','options':{'type':'terms','multiselect':False,'dynamicOptions':True,'size':5,'order':'desc'}}
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
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps(search_source)}
        }
    
    def so_line(vid, attrs):
        return json.dumps({
            'type': 'visualization',
            'id': vid,
            'attributes': attrs,
            'references': []
        })
    
    # Direct PUT overwrite for each visualization
    results = {}
    for vid, vs in [
        ('filters', filters_vs),
        ('allcountries', region_map_vs('Countries By Number of Request')),
        ('blockedcountries', region_map_vs('Countries By Number of BLOCKED Request')),
        ('top10countries', table_vs),
        ('top10webacl', asn_vs)
    ]:
        logger.info(f"Processing visualization id={vid}")
        
        # Prepare the payload
        attrs = attributes_for_vs(vs)
        payload = {
            'attributes': attrs,
            'references': []
        }
        payload_json = json.dumps(payload).encode('utf-8')
        
        # PUT the visualization
        put_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/{vid}?overwrite=true"
        put_headers = headers.copy()
        put_headers['Content-Type'] = 'application/json'
        
        status_code, response_body = make_signed_request('PUT', put_url, headers=put_headers, data=payload_json)
        
        if status_code != 200:
            logger.warning(f"PUT failed for {vid}: {status_code} {response_body}")
            
            # Try POST as fallback
            post_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/{vid}?overwrite=true"
            status_code, response_body = make_signed_request('POST', post_url, headers=put_headers, data=payload_json)
            
            if status_code != 200:
                logger.warning(f"POST failed for {vid}: {status_code} {response_body}")
            else:
                logger.info(f"POST succeeded for {vid}")
        else:
            logger.info(f"PUT succeeded for {vid}")
        
        # Verify the visualization
        get_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/{vid}"
        status_code, response_body = make_signed_request('GET', get_url, headers=headers)
        ok = False
        if status_code == 200:
            try:
                data = json.loads(response_body)
                vs_text = data.get('attributes', {}).get('visState', '') or ''
                expected = 'real_country_code'
                if vid == 'top10webacl':
                    expected = 'req_asn'
                ok = (expected in vs_text)
            except Exception as e:
                logger.warning(f"Error parsing response for {vid}: {e}")
        else:
            logger.warning(f"GET verification failed for {vid}: {status_code}")
        results[vid] = ok
        logger.info(f"verify {vid}: real_country_code={ok}")

    # If ASN viz failed verification, force delete+recreate
    try:
        if not results.get('top10webacl', True):
            headers = {
                'osd-xsrf': 'true', 'kbn-xsrf': 'true', 'kbn-version': '7.10.2', 'osd-version': '1.0.0', 'Content-Type': 'application/json'
            }
            # build attrs again
            attrs = attributes_for_vs(asn_vs)
            payload = json.dumps({'attributes': attrs, 'references': []}).encode('utf-8')
            del_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/top10webacl"
            sc, body = make_signed_request('DELETE', del_url, headers=headers)
            logger.info('force delete top10webacl status=%s', sc)
            post_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/top10webacl?overwrite=true"
            sc, body = make_signed_request('POST', post_url, headers=headers, data=payload)
            logger.info('force recreate top10webacl status=%s', sc)
            # re-verify
            gu = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/visualization/top10webacl"
            sc, body = make_signed_request('GET', gu, headers=headers)
            ok = False
            if sc == 200:
                try:
                    vs_text = json.loads(body).get('attributes', {}).get('visState', '') or ''
                    ok = ('req_asn' in vs_text)
                except Exception:
                    ok = False
            results['top10webacl'] = ok
            logger.info('verify (post-recreate) top10webacl: %s', ok)
    except Exception as e:
        logger.warning('top10webacl force recreate failed: %s', e)
    return results

def ensure_index_pattern_timefield(pattern_title: str = 'awswaf-*', time_field: str = '@timestamp'):
    headers = {
        'osd-xsrf': 'true',
        'kbn-xsrf': 'true',
        'kbn-version': '7.10.2',
        'osd-version': '1.0.0',
        'Content-Type': 'application/json'
    }
    pid = find_index_pattern_id(pattern_title)
    if not pid:
        logger.warning('Index pattern not found for title=%s', pattern_title)
        return False
    url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/index-pattern/{pid}?overwrite=true"
    payload = json.dumps({'attributes': {'timeFieldName': time_field}}).encode('utf-8')
    sc, body = make_signed_request('PUT', url, headers=headers, data=payload)
    ok = (sc >= 200 and sc < 300)
    logger.info('ensure_index_pattern_timefield id=%s status=%s body=%s', pid, sc, (body[:120] if isinstance(body, str) else body))
    return ok

def lambda_handler(event, context):
    """Lambda handler: enforce visuals and index pattern consistently."""
    try:
        # set correct time field and enforce visuals
        try:
            ensure_index_pattern_timefield('awswaf-*', '@timestamp')
        except Exception:
            pass
        results = import_country_objects()
        try:
            ensure_top20asn_panel_on_dashboard('WAFDashboard', 'top10webacl')
        except Exception:
            pass
        return {"status": "ok", "verified": results}
    except Exception as e:
        logger.exception("Error in lambda_handler")
        return {"status": "error", "message": str(e)}


def ensure_top20asn_panel_on_dashboard(dashboard_title: str, viz_id: str):
    headers = {
        'osd-xsrf': 'true',
        'kbn-xsrf': 'true',
        'kbn-version': '7.10.2',
        'osd-version': '1.0.0',
        'Content-Type': 'application/json'
    }
    # find dashboard id by title
    find_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/_find"
    sc, body = make_signed_request('GET', find_url, headers=headers, params={'type':'dashboard','search_fields':'title','search':dashboard_title})
    if sc != 200:
        logger.warning('ensure_top20asn_panel: find dashboard failed status=%s body=%s', sc, (body[:120] if isinstance(body,str) else body))
        return False
    did = None
    try:
        data = json.loads(body)
        for so in data.get('saved_objects', []):
            if so.get('attributes', {}).get('title') == dashboard_title:
                did = so.get('id')
                break
    except Exception:
        pass
    if not did:
        logger.warning('ensure_top20asn_panel: dashboard title=%s not found', dashboard_title)
        return False
    # get dashboard
    get_url = f"https://{ES_ENDPOINT}//_dashboards/api/saved_objects/dashboard/{did}"
    sc, body = make_signed_request('GET', get_url, headers=headers)
    if sc != 200:
        logger.warning('ensure_top20asn_panel: get dashboard failed status=%s body=%s', sc, (body[:120] if isinstance(body,str) else body))
        return False
    attr = json.loads(body).get('attributes', {})
    panels = []
    try:
        panels = json.loads(attr.get('panelsJSON') or '[]')
    except Exception:
        panels = []
    # already present?
    for p in panels:
        if p.get('id') == viz_id:
            logger.info('ensure_top20asn_panel: panel already present')
            return True
    # append a new panel roughly at bottom-right
    panel = {
        'embeddableConfig': {},
        'gridData': {'h': 12, 'w': 12, 'x': 36, 'y': 72, 'i': 'asn'},
        'id': viz_id,
        'panelIndex': 'asn',
        'type': 'visualization',
        'version': '6.7.0'
    }
    panels.append(panel)
    attr['panelsJSON'] = json.dumps(panels)
    put_url = f"https://{ES_ENDPOINT}/_dashboards/api/saved_objects/dashboard/{did}?overwrite=true"
    payload = json.dumps({'attributes': {'panelsJSON': attr['panelsJSON']}}).encode('utf-8')
    sc, body = make_signed_request('PUT', put_url, headers=headers, data=payload)
    ok = (sc >= 200 and sc < 300)
    logger.info('ensure_top20asn_panel: update status=%s', sc)
    return ok

if __name__ == "__main__":
    # For local testing
    import_country_objects()
