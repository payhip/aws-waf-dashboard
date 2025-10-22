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
 
The first time you deploy an AWS CDK app into an environment (account and AWS Region), you’ll need to install a bootstrap stack. This stack includes resources that are needed for the toolkit’s operation. For example, the stack includes an Amazon Simple Storage Services (Amazon S3) bucket that is used to store templates and assets during the deployment process.

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

The dashboard should still be empty because it hasn’t connected with AWS WAF yet.

#### Connect WAF logs
To connect to AWS WAF logs
1.	Open the AWS WAF console and choose Web ACLs. Then choose your desired web ACL.
2.	If you haven’t enabled AWS WAF logs yet, you need to do so now in order to continue. To do this, choose the Logging and metrics tab in your web ACL, and then choose Enable.
3.	For Amazon Kinesis Data Firehose delivery stream, select the Kinesis Firehose that was created by the template in Step 1. Its name starts with aws-waf-logs. 
4.	Save your changes.

#### Final result
That's all! Now, your WAF logs will be send from WAF service throug Kinesis Firehose directly to the OpenSearch cluster and will become available to you using OpenSearch dashboards. After a couple of minutes, you should start seeing that your dashboards have got data on it.

Important! By the default, OpenSearch dashboard will be publicly accessible from Internet (although only Administrator will be able to create users who will be able to log in via Cognito). In production environment, we recomend to put a proxy in front of it, to allow access only from specific IP addresses.

<img src="graphics/3.png" width="700">

## Testing and Endpoints

- **OpenSearch Dashboards URL**: `https://search-osdfw-opensearch-domain-o4qqwqklqckzntadqra5u77axa.us-east-1.es.amazonaws.com/_dashboards`
- **Login (example)**: `hamzaawanit@gmail.com` / `HAMZAawan@123`
- In Dashboards, open `WAFDashboard`, set time to **Last 15 minutes**, then click **Refresh**.

### Finding your application hostname (your-app-hostname)
- **If using CloudFront**: Console → CloudFront → Distributions → copy the Distribution Domain name (e.g., `dxxxxx.cloudfront.net`).
- **If using ALB**: Console → EC2 → Load Balancers → select your ALB → copy the **DNS name** (e.g., `my-alb-1234.us-east-1.elb.amazonaws.com`). If the app expects a custom hostname, add a `Host` header in curl (see below).

### Generate test traffic (cURL)
Replace placeholders before running.

Basic (sets client IP explicitly):

```bash
curl -k -sS \
  -H "User-Agent: Client-Demo" \
  -H "True-Client-IP: 203.0.113.77" \
  -H "X-Forwarded-For: 203.0.113.77, 10.0.0.5" \
  https://<your-app-hostname>/test
```

ALB DNS with app Host header:

```bash
curl -k -sS \
  -H "Host: <your-app-hostname>" \
  -H "True-Client-IP: 203.0.113.77" \
  -H "X-Forwarded-For: 203.0.113.77" \
  https://<your-alb-dns-name>/test
```

After 1–2 requests, refresh the dashboard. You should see `Top 10 IP Addresses` populated with `true_client_ip` and associated metrics.

### Rebuild customizer Lambda ZIP and deploy

The CDK stacks reference `assets/os-customizer-lambda-fixed.zip` (see `src/main/java/com/myorg/AppStack.java`). Rebuild the ZIP from the current sources in `assets/src/` before deploying:

```bash
# From project root
BUILD_DIR=assets/os-customizer-build
ZIP_OUT=assets/os-customizer-lambda-fixed.zip

rm -rf "$BUILD_DIR" && mkdir -p "$BUILD_DIR"
pip install --upgrade -t "$BUILD_DIR" requests furl requests-aws4auth
cp -R assets/src/* "$BUILD_DIR"/
(cd "$BUILD_DIR" && zip -r ../os-customizer-lambda-fixed.zip .)

# Deploy (adjust parameters)
cdk deploy --parameters osdfwDashboardsAdminEmail=<yourEmail> --parameters osdfwCognitoDomain=<uniqueCognitoDomain>

### Post-deploy maintenance (required after any code pull/deploy)

After deploying or pulling latest code, run the updater Lambda maintenance once to ensure saved objects and Data View are normalized to canonical fields.

- Console (recommended):

```
Lambda → us-east-1 → function:
OSDfW-AppNestedStackAppNe-osdfwDashboardsUpdater66-asodKL6y7dOC

Test event JSON:
{
  "Action": "RefreshAndNormalize"
}
```

- AWS CLI v2:

```bash
aws lambda invoke \
  --region us-east-1 \
  --function-name OSDfW-AppNestedStackAppNe-osdfwDashboardsUpdater66-asodKL6y7dOC \
  --cli-binary-format raw-in-base64-out \
  --payload '{"Action":"RefreshAndNormalize"}' \
  /dev/stdout
```

- Python one-liner:

```bash
python3 -c "import boto3, json; print(boto3.client('lambda', region_name='us-east-1').invoke(FunctionName='OSDfW-AppNestedStackAppNe-osdfwDashboardsUpdater66-asodKL6y7dOC', Payload=json.dumps({'Action':'RefreshAndNormalize'}).encode()).get('Payload').read().decode())"
```

Then refresh the Data View field cache:

- OpenSearch Dashboards → Stack Management → Data Views → open `awswaf-*` → click “Refresh field list” → Save.
- Hard refresh the browser and open `WAFDashboard`.

### What maintenance does

- Purges/recycles saved objects to latest definitions under `assets/src/dashboards_definitions_json/`.
- Removes scripted fields and scripted filters.
- Normalizes fields to canonical names used by the index (examples):
  - `httpRequest.clientIp(.keyword)` → `true_client_ip`
  - `httpRequest.country.keyword` → `real_country_code`
  - `httpRequest.uri.keyword` → `uri`
  - `httpRequest.httpMethod.keyword`/`method` → `httpMethod`
  - `httpRequest.httpVersion.keyword`/`version` → `httpVersion`
  - `httpRequest.host(.keyword)`/`Host` → `host`
  - `action(.keyword)` → `action`

### Troubleshooting

- If a panel shows “Could not locate index-pattern-field …”, run the maintenance action and refresh the Data View as above.
- If Filters controls fail to fetch terms, check they reference `action`, `real_country_code`, `true_client_ip`, and (if present) `host`.
