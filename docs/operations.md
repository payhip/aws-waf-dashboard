# AWS WAF Dashboard Operations Guide

## Ingest Pipeline Configuration

The AWS WAF Dashboard uses an OpenSearch ingest pipeline to process WAF logs and extract key fields. The pipeline is configured to handle both map and list header formats from WAF logs.

### Pipeline Details

- **Pipeline Name**: `extract_true_client_ip`
- **Used By**: Default pipeline in the `awswaf*` index template
- **Key Functions**:
  - Extracts client IP from `True-Client-IP` or `x-forwarded-for` headers
  - Extracts country code from `CF-IPCountry` header
  - Sets `@timestamp` from the WAF log `timestamp` field
  - Populates fields:
    - `client.ip` - Client IP address (type: ip)
    - `true_client_ip` - Client IP as string (type: keyword)
    - `cloudflare.country` - Country code (type: keyword)
    - `real_country_code` - Country code duplicate (type: keyword)

## Post-Deployment Steps

After deploying the AWS WAF Dashboard, follow these steps to ensure proper data visualization:

1. **Set Time Field for Index Pattern**:
   - Navigate to OpenSearch Dashboards → Stack Management → Index patterns
   - Open the `awswaf*` index pattern
   - Set Time field to `@timestamp`
   - Click "Refresh field list"

2. **Verify Field Mappings**:
   - Confirm the following fields are present and properly mapped:
     - `@timestamp` (type: date)
     - `client.ip` (type: ip)
     - `true_client_ip` (type: keyword)
     - `cloudflare.country` (type: keyword)
     - `real_country_code` (type: keyword)
     - `action` (type: string)
     - `action.keyword` (type: keyword)

3. **Dashboard Visualization Fields**:
   - Time series charts: Use Date histogram on `@timestamp`
   - Top IPs: Terms aggregation on `client.ip`
   - Actions (Allow/Block): Terms aggregation on `action.keyword`
   - Countries: Terms aggregation on `cloudflare.country` or `real_country_code`

## Troubleshooting

### Common Issues

1. **Missing Fields in Discover**:
   - Refresh field list in the index pattern
   - Check that the ingest pipeline is correctly set as the default pipeline

2. **"Field Not Found" in Visualizations**:
   - For text fields, use the `.keyword` variant (e.g., `action.keyword`)
   - For IP fields, use `client.ip` directly (no `.keyword` needed)

3. **400 Errors in Firehose Delivery**:
   - Check CloudWatch Logs for the Firehose delivery stream
   - Verify the ingest pipeline script is handling both list and map header formats

### Monitoring

- Check Firehose delivery metrics for delivery success/failure rates
- Monitor OpenSearch cluster health and index growth
- Review CloudWatch Logs for any script exceptions in the pipeline

## Data Retention

By default, indices follow the pattern `awswaf-YYYY-MM-DD`. Consider implementing an Index State Management (ISM) policy for data retention if needed.
