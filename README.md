# AWS WAF Dashboard

## Description

AWS WAF Dashboards are ready to use dashboards (build on Amazon OpenSearch Service with OpenSearch Dashboards) which can be quickly connected to already existing AWS WAF configuration and allow visualization of AWS WAF Logs with multiple build in visualization diagrams.

To start using  AWS WAF Dashboards you don't need to have any prior experience with Amazon OpenSearch or even AWS WAF, minimal AWS knowledge is require. You just need to run AWS CDK commands - which will do all the rest. The whole process takes around 30 minutes (with 25 minutes of waiting).

*Note:* You will need to launch the AWS CDK project in the us-east-1 AWS Region if you are using an AWS WAF web ACL that is associated to an Amazon CloudFront distribution. Otherwise, you have the option to launch the AWS CDK project in any AWS Region that supports the AWS services to be deployed.

## Installation

#### Deploy the solution by using the AWS CDK
We provide an AWS Cloud Development Kit (AWS CDK) project that you will deploy to set up the whole solution automatically in your preferred AWS account. 

Use the integrated development environment (IDE) of your choice. Make sure you have set up your environment with all the prerequisites of working with the AWS CDK. This particular AWS CDK project is written in Java, so make sure to also check the prerequisites for working with the CDK in Java. 

To deploy the solution
1.	Clone the repo by running the following command.

```
git clone https://github.com/aws-samples/aws-waf-dashboard.git 
```
2.	Navigate into the cloned project folder by running the following command.

```
cd aws-waf-dashboard
```
3.	Run the cdk commands to deploy the infrastructure.
 
The first time you deploy an AWS CDK app into an environment (account and AWS Region), you'll need to install a bootstrap stack. This stack includes resources that are needed for the toolkit's operation. For example, the stack includes an Amazon Simple Storage Services (Amazon S3) bucket that is used to store templates and assets during the deployment process.

Run the following command to bootstrap your environment.
```
cdk bootstrap
```
4.	After the bootstrap command has completed, you can start deploying the solution. You will need to pass two parameters with your deployment command: 
•	The email that you will use as your username.
•	The Cognito domain. You can enter the name of your choice for the Cognito domain. 

Note that the Cognito domain name you choose will serve as a domain prefix for the Cognito hosted UI URL and needs to be unique. See Configuring a user pool domain in the Amazon Cognito User Guide if you need more information on Cognito domains.

Run the following command:

```
cdk deploy --parameters osdfwDashboardsAdminEmail=<yourEmail> --parameters osdfwCognitoDomain=<uniqueCognitoDomain>
```
Type *y* and press enter when prompted if you wish to deploy the changes.

There are three more optional AWS CDK deployment parameters that have default values. You can use these parameters in addition to the mandatory parameters (the email and Cognito domain). The additional parameters are the following:	

•	**EBS size for the OpenSearch Service cluster:** *osdfwOsEbsSize*

•	**Node type for the OpenSearch Service cluster:** *osdfwOsNodeSize*

•	**OpenSearchDomainName:** *osdfwOsDomainName*

#### Verify that the OpenSearch dashboard works
To test the OpenSearch dashboard:
1.	First, check the email address that you provided in the parameter for *osdfwDashboardsAdminEmail*. You should have received an email with the required password to log in to the OpenSearch dashboard. Make a note of it. 

2.	Now return to the environment where you ran the AWS CDK deployment. There should be a link under Outputs, as shown in the graphic below:

<img src="graphics/1.png" width="400">

3.	Select the link and log into the OpenSearch dashboard. Provide the email address that you set up in Step 1 and the password that was sent to it. You will be prompted to update the password.

4.	In the OpenSearch dashboard, choose the OpenSearch Dashboards logo (the burger icon) at the top left. Then under Dashboards, choose WAFDashboard. This will display the AWS WAF dashboard.

<img src="graphics/2.png" width="400">

The dashboard should still be empty because it hasn't connected with AWS WAF yet.

#### Connect WAF logs
To connect to AWS WAF logs
1.	Open the AWS WAF console and choose Web ACLs. Then choose your desired web ACL.
2.	If you haven't enabled AWS WAF logs yet, you need to do so now in order to continue. To do this, choose the Logging and metrics tab in your web ACL, and then choose Enable.
3.	For Amazon Kinesis Data Firehose delivery stream, select the Kinesis Firehose that was created by the template in Step 1. Its name starts with aws-waf-logs. 
4.	Save your changes.

#### Final result
That's all! Now, your WAF logs will be send from WAF service throug Kinesis Firehose directly to the OpenSearch cluster and will become available to you using OpenSearch dashboards. After a couple of minutes, you should start seeing that your dashboards have got data on it.

Important! By the default, OpenSearch dashboard will be publicly accessible from Internet (although only Administrator will be able to create users who will be able to log in via Cognito). In production environment, we recomend to put a proxy in front of it, to allow access only from specific IP addresses.

<img src="graphics/3.png" width="700">

## Testing the Dashboard

### Prerequisites
- Access to AWS Console (WAF, Firehose, OpenSearch)
- Access to OpenSearch Dashboards
- An ALB with WAF enabled

### Step 1: Generate Test Traffic
Send requests to your ALB with custom headers to simulate Cloudflare:

```bash
# Replace ALB_DNS with your ALB endpoint
ALB_DNS=your-alb-endpoint.us-east-1.elb.amazonaws.com

# Send 50 test requests with True-Client-IP and CF-IPCountry headers
for i in {1..50}; do
  curl -s "http://$ALB_DNS/" \
    -H "True-Client-IP: $(curl -s https://checkip.amazonaws.com)" \
    -H "CF-IPCountry: US" \
    -H "User-Agent: waf-test/1.0" >/dev/null &
done
wait
echo "Test traffic sent"
```

### Step 2: Verify Data Ingestion
1. Wait 1-2 minutes for Firehose buffer to flush
2. Open OpenSearch Dashboards
3. Go to Discover
   - Index pattern: `awswaf*`
   - Time range: Last 15 minutes
4. Verify fields are present:
   - `@timestamp`
   - `client.ip` (should match your public IP)
   - `true_client_ip` (should match your public IP)
   - `cloudflare.country` (should be "US")
   - `real_country_code` (should be "US")
   - `action` (should show "ALLOW" or "BLOCK")

### Step 3: Check Dashboard Visualizations
1. Open "WAF - Overview (client.ip, country, actions)" dashboard
2. Verify all panels render without errors:
   - Top source IPs chart shows your IP
   - Actions split shows ALLOW/BLOCK counts
   - Events table shows recent requests
3. Test filters:
   - Filter by your client IP
   - Filter by country code "US"
   - Filter by action "ALLOW"

### Step 4: Verify No Delivery Errors
1. Open AWS Console → Kinesis Firehose
2. Select your delivery stream `aws-waf-logs-osdfw`
3. Go to "Destination error logs"
4. Filter by "Last 15 minutes"
5. Confirm no new 400 errors appear

### Troubleshooting
- If fields are missing in Discover:
  - Go to Stack Management → Index patterns → `awswaf*`
  - Set Time field to `@timestamp`
  - Click "Refresh field list"
- If visualizations show "field not found" errors:
  - Edit the visualization
  - For Terms aggregation on text fields, use the `.keyword` variant (e.g., `action.keyword`)
  - For IP fields, use `client.ip` directly (no `.keyword` needed)



# AWS WAF Dashboard

## Description

AWS WAF Dashboards are ready to use dashboards (build on Amazon OpenSearch Service with OpenSearch Dashboards) which can be quickly connected to already existing AWS WAF configuration and allow visualization of AWS WAF Logs with multiple build in visualization diagrams.

To start using  AWS WAF Dashboards you don't need to have any prior experience with Amazon OpenSearch or even AWS WAF, minimal AWS knowledge is require. You just need to run AWS CDK commands - which will do all the rest. The whole process takes around 30 minutes (with 25 minutes of waiting).

*Note:* You will need to launch the AWS CDK project in the us-east-1 AWS Region if you are using an AWS WAF web ACL that is associated to an Amazon CloudFront distribution. Otherwise, you have the option to launch the AWS CDK project in any AWS Region that supports the AWS services to be deployed.

## Installation

#### Deploy the solution by using the AWS CDK
We provide an AWS Cloud Development Kit (AWS CDK) project that you will deploy to set up the whole solution automatically in your preferred AWS account. 

Use the integrated development environment (IDE) of your choice. Make sure you have set up your environment with all the prerequisites of working with the AWS CDK. This particular AWS CDK project is written in Java, so make sure to also check the prerequisites for working with the CDK in Java. 

To deploy the solution
1.	Clone the repo by running the following command.

```
git clone https://github.com/aws-samples/aws-waf-dashboard.git 
```
2.	Navigate into the cloned project folder by running the following command.

```
cd aws-waf-dashboard
```
3.	Run the cdk commands to deploy the infrastructure.
 
The first time you deploy an AWS CDK app into an environment (account and AWS Region), you'll need to install a bootstrap stack. This stack includes resources that are needed for the toolkit's operation. For example, the stack includes an Amazon Simple Storage Services (Amazon S3) bucket that is used to store templates and assets during the deployment process.

Run the following command to bootstrap your environment.
```
cdk bootstrap
```
4.	After the bootstrap command has completed, you can start deploying the solution. You will need to pass two parameters with your deployment command: 
•	The email that you will use as your username.
•	The Cognito domain. You can enter the name of your choice for the Cognito domain. 

Note that the Cognito domain name you choose will serve as a domain prefix for the Cognito hosted UI URL and needs to be unique. See Configuring a user pool domain in the Amazon Cognito User Guide if you need more information on Cognito domains.

Run the following command:

```
cdk deploy --parameters osdfwDashboardsAdminEmail=<yourEmail> --parameters osdfwCognitoDomain=<uniqueCognitoDomain>
```
Type *y* and press enter when prompted if you wish to deploy the changes.

There are three more optional AWS CDK deployment parameters that have default values. You can use these parameters in addition to the mandatory parameters (the email and Cognito domain). The additional parameters are the following:	

•	**EBS size for the OpenSearch Service cluster:** *osdfwOsEbsSize*

•	**Node type for the OpenSearch Service cluster:** *osdfwOsNodeSize*

•	**OpenSearchDomainName:** *osdfwOsDomainName*

#### Verify that the OpenSearch dashboard works
To test the OpenSearch dashboard:
1.	First, check the email address that you provided in the parameter for *osdfwDashboardsAdminEmail*. You should have received an email with the required password to log in to the OpenSearch dashboard. Make a note of it. 

2.	Now return to the environment where you ran the AWS CDK deployment. There should be a link under Outputs, as shown in the graphic below:

<img src="graphics/1.png" width="400">

3.	Select the link and log into the OpenSearch dashboard. Provide the email address that you set up in Step 1 and the password that was sent to it. You will be prompted to update the password.

4.	In the OpenSearch dashboard, choose the OpenSearch Dashboards logo (the burger icon) at the top left. Then under Dashboards, choose WAFDashboard. This will display the AWS WAF dashboard.

<img src="graphics/2.png" width="400">

The dashboard should still be empty because it hasn't connected with AWS WAF yet.

#### Connect WAF logs
To connect to AWS WAF logs
1.	Open the AWS WAF console and choose Web ACLs. Then choose your desired web ACL.
2.	If you haven't enabled AWS WAF logs yet, you need to do so now in order to continue. To do this, choose the Logging and metrics tab in your web ACL, and then choose Enable.
3.	For Amazon Kinesis Data Firehose delivery stream, select the Kinesis Firehose that was created by the template in Step 1. Its name starts with aws-waf-logs. 
4.	Save your changes.

#### Final result
That's all! Now, your WAF logs will be send from WAF service throug Kinesis Firehose directly to the OpenSearch cluster and will become available to you using OpenSearch dashboards. After a couple of minutes, you should start seeing that your dashboards have got data on it.

Important! By the default, OpenSearch dashboard will be publicly accessible from Internet (although only Administrator will be able to create users who will be able to log in via Cognito). In production environment, we recomend to put a proxy in front of it, to allow access only from specific IP addresses.

<img src="graphics/3.png" width="700">

## Testing the Dashboard

### Prerequisites
- Access to AWS Console (WAF, Firehose, OpenSearch)
- Access to OpenSearch Dashboards
- An ALB with WAF enabled

### Step 1: Generate Test Traffic
Send requests to your ALB with custom headers to simulate Cloudflare:

```bash
# Replace ALB_DNS with your ALB endpoint
ALB_DNS=your-alb-endpoint.us-east-1.elb.amazonaws.com

# Send 50 test requests with True-Client-IP and CF-IPCountry headers
for i in {1..50}; do
  curl -s "http://$ALB_DNS/" \
    -H "True-Client-IP: $(curl -s https://checkip.amazonaws.com)" \
    -H "CF-IPCountry: US" \
    -H "User-Agent: waf-test/1.0" >/dev/null &
done
wait
echo "Test traffic sent"
```

### Step 2: Verify Data Ingestion
1. Wait 1-2 minutes for Firehose buffer to flush
2. Open OpenSearch Dashboards
3. Go to Discover
   - Index pattern: `awswaf*`
   - Time range: Last 15 minutes
4. Verify fields are present:
   - `@timestamp`
   - `client.ip` (should match your public IP)
   - `true_client_ip` (should match your public IP)
   - `cloudflare.country` (should be "US")
   - `real_country_code` (should be "US")
   - `action` (should show "ALLOW" or "BLOCK")

### Step 3: Check Dashboard Visualizations
1. Open "WAF - Overview (client.ip, country, actions)" dashboard
2. Verify all panels render without errors:
   - Top source IPs chart shows your IP
   - Actions split shows ALLOW/BLOCK counts
   - Events table shows recent requests
3. Test filters:
   - Filter by your client IP
   - Filter by country code "US"
   - Filter by action "ALLOW"

### Step 4: Verify No Delivery Errors
1. Open AWS Console → Kinesis Firehose
2. Select your delivery stream `aws-waf-logs-osdfw`
3. Go to "Destination error logs"
4. Filter by "Last 15 minutes"
5. Confirm no new 400 errors appear

### Troubleshooting
- If fields are missing in Discover:
  - Go to Stack Management → Index Patterns → `awswaf*`
  - Set Time field to `@timestamp`
  - Click "Refresh field list"
- If visualizations show "field not found" errors:
  - Edit the visualization
  - For Terms aggregation on text fields, use the `.keyword` variant (e.g., `action.keyword`)
  - For IP fields, use `client.ip` directly (no `.keyword` needed)

## Implementation Notes

### CloudFormation Stack Management
When deploying this solution, it's important to use unique stack names to avoid conflicts with existing stacks. If you encounter issues with stack deployment:

1. Check for existing stacks in DELETE_IN_PROGRESS or ROLLBACK_IN_PROGRESS state
2. Wait for deletion to complete or manually delete resources if needed
3. Use a completely different stack name for new deployments

### OpenSearch Configuration
After deploying the solution, you need to configure OpenSearch:

1. **Create the ingest pipeline**:
   ```
   PUT _ingest/pipeline/extract_true_client_ip
   {
     "description": "Extract True-Client-IP/XFF + CF-IPCountry; set @timestamp (supports map or list headers)",
     "processors": [
       {
         "script": {
           "lang": "painless",
           "source": "def getFromMap(def headersMap, String key) {...}"
         }
       }
     ]
   }
   ```

2. **Create the index template**:
   ```
   PUT _index_template/awswaf
   {
     "index_patterns": ["awswaf*"],
     "template": {
       "settings": {
         "index": {
           "number_of_shards": "1",
           "default_pipeline": "extract_true_client_ip"
         }
       },
       "mappings": {...}
     },
     "priority": 400
   }
   ```

3. **Create a test index** to verify configuration:
   ```
   PUT awswaf-test
   {
     "mappings": {
       "properties": {
         "@timestamp": { "type": "date" },
         "timestamp": { "type": "date" },
         "client": { 
           "properties": { 
             "ip": { "type": "ip" } 
           } 
         },
         "true_client_ip": { "type": "keyword" },
         "cloudflare": { 
           "properties": { 
             "country": { "type": "keyword" } 
           } 
         },
         "real_country_code": { "type": "keyword" }
       }
     }
   }
   ```

### Cognito Authentication
If you encounter issues with Cognito authentication:

1. Check if the Cognito domain is active:
   ```bash
   aws cognito-idp describe-user-pool-domain --domain your-domain-name
   ```

2. If the domain is not active, create a new one:
   ```bash
   aws cognito-idp create-user-pool-domain --domain your-new-domain --user-pool-id your-user-pool-id
   ```

3. Wait a few minutes for the CloudFront distribution to propagate

### Time Range Configuration
When viewing data in OpenSearch Dashboards:

1. Make sure to set an appropriate time range that includes your data
2. For testing, use "Absolute" time range and set dates that include your test data
3. For production, use relative time ranges like "Last 24 hours" or "Last 7 days"

### Recommended Visualizations
For optimal WAF monitoring, create these visualizations:

1. **Pie Chart** - For actions (ALLOW vs BLOCK)
2. **Vertical Bar** - For top source IPs and user agents
3. **Line Chart** - For requests over time
4. **Region Map** - For geographical distribution of requests
5. **Data Table** - For detailed request information
