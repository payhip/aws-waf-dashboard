package com.myorg;

import software.amazon.awscdk.services.events.EventPattern;
import software.amazon.awscdk.services.events.Rule;
import software.amazon.awscdk.services.events.Schedule;
import software.amazon.awscdk.services.events.CronOptions;
import software.amazon.awscdk.services.events.targets.LambdaFunction;
import software.amazon.awscdk.services.iam.*;
import software.amazon.awscdk.services.lambda.Runtime;
import software.amazon.awscdk.services.lambda.*;
import software.amazon.awscdk.services.logs.RetentionDays;
import software.constructs.Construct;
import software.amazon.awscdk.NestedStack;

import software.amazon.awscdk.CustomResource;
import software.amazon.awscdk.RemovalPolicy;
import software.amazon.awscdk.Duration;
import software.amazon.awscdk.customresources.AwsCustomResource;
import software.amazon.awscdk.customresources.AwsCustomResourcePolicy;
import software.amazon.awscdk.customresources.AwsSdkCall;
import software.amazon.awscdk.customresources.PhysicalResourceId;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * AWS WAF Dashboards Solution - creates the ingest pipeline and index template automatically during deploy.
 */
public class AppStack extends NestedStack {
    public Function dashboardsCustomizerLambda;

    public AppStack(Construct scope, String id, StreamStackProps props) {
        super(scope, id, props);

        Code lambdaCodeLocation = Code.fromAsset("assets/os-customizer-lambda-fixed.zip");
        //Code lambdaCodeLocation = Code.fromBucket(Bucket.fromBucketArn(this, "id", "arn:aws:s3:::aws-waf-dashboard-resources"), "os-customizer-lambda.zip");
        //Code lambdaCodeLocation = Code.fromBucket(Bucket.fromBucketArn(this, "id", "arn:aws:s3:::waf-dashboards-" + this.getRegion()), "os-customizer-lambda.zip");

        Role customizerRole = createLambdaRole();

        this.dashboardsCustomizerLambda = Function.Builder.create(this, "osdfwDashboardsSeeder")
                .architecture(Architecture.ARM_64)
                .description("AWS WAF Dashboards Solution main function")
                .handler("lambda_function.handler")
                .logRetention(RetentionDays.ONE_MONTH)
                .role(customizerRole) //todo
                .code(lambdaCodeLocation)
                .runtime(Runtime.PYTHON_3_9)
                .memorySize(128)
                .timeout(Duration.seconds(600))
                .environment(Map.of(
                        "ES_ENDPOINT", props.getOpenSearchDomain().getDomainEndpoint(),
                        "REGION", this.getRegion(),
                        "ACCOUNT_ID", this.getAccount()
                ))
                .build();

        createCustomizer(dashboardsCustomizerLambda, props);

        Function customizerUpdaterLambda = Function.Builder.create(this, "osdfwDashboardsUpdater")
                .architecture(Architecture.ARM_64)
                .description("AWS WAF Dashboards Solution updater function")
                .handler("lambda_function.update")
                .logRetention(RetentionDays.ONE_MONTH)
                .role(customizerRole) //todo
                .code(lambdaCodeLocation)
                .runtime(Runtime.PYTHON_3_9)
                .memorySize(128)
                .timeout(Duration.seconds(600))
                .environment(Map.of(
                        "ES_ENDPOINT", props.getOpenSearchDomain().getDomainEndpoint(),
                        "REGION", this.getRegion(),
                        "ACCOUNT_ID", this.getAccount()
                ))
                .build();

        List<Rule> eventRules = createEvents(customizerUpdaterLambda);

        for (Rule rule : eventRules) {
            customizerUpdaterLambda.addPermission(
                    rule.getRuleName().toLowerCase(Locale.ROOT),
                    Permission.builder()
                            .action("lambda:InvokeFunction")
                            .principal(new ServicePrincipal("events.amazonaws.com"))
                            .sourceArn(rule.getRuleArn())
                            .build());
        }

        Function dashboardsFixerLambda = Function.Builder.create(this, "osdfwDashboardsFixer")
                .architecture(Architecture.X86_64)
                .description("Enforce country visuals to use real_country_code")
                .handler("fix_country_objects.lambda_handler")
                .logRetention(RetentionDays.ONE_MONTH)
                .role(customizerRole)
                .code(Code.fromAsset("assets/os-customizer-build"))
                .runtime(Runtime.PYTHON_3_9)
                .memorySize(128)
                .timeout(Duration.seconds(300))
                .environment(Map.of(
                        "ES_ENDPOINT", props.getOpenSearchDomain().getDomainEndpoint(),
                        "REGION", this.getRegion()
                ))
                .build();

        Rule dashboardsFixerNightly = Rule.Builder.create(this, "osdfwDashboardsFixerNightlyCFN")
                .description("Nightly enforcement of country visuals (real_country_code)")
                .schedule(Schedule.cron(CronOptions.builder().minute("0").hour("3").build()))
                .targets(List.of(LambdaFunction.Builder.create(dashboardsFixerLambda).build()))
                .enabled(true)
                .build();

        dashboardsFixerLambda.addPermission(
                "allowEventsInvokeNightly",
                Permission.builder()
                        .action("lambda:InvokeFunction")
                        .principal(new ServicePrincipal("events.amazonaws.com"))
                        .sourceArn(dashboardsFixerNightly.getRuleArn())
                        .build());

        // Post-deploy auto-invoke via AWS SDK custom resource (runs on Create/Update)
        AwsSdkCall invokeOnCreate = AwsSdkCall.builder()
                .service("Lambda")
                .action("invoke")
                .parameters(Map.of(
                        "FunctionName", dashboardsFixerLambda.getFunctionName(),
                        "InvocationType", "Event",
                        "Payload", "{}"
                ))
                .physicalResourceId(PhysicalResourceId.of("InvokeDashboardsFixerOnDeploy"))
                .build();

        AwsSdkCall invokeOnUpdate = AwsSdkCall.builder()
                .service("Lambda")
                .action("invoke")
                .parameters(Map.of(
                        "FunctionName", dashboardsFixerLambda.getFunctionName(),
                        "InvocationType", "Event",
                        "Payload", "{}"
                ))
                .physicalResourceId(PhysicalResourceId.of("InvokeDashboardsFixerOnDeploy"))
                .build();

        AwsCustomResource.Builder.create(this, "InvokeDashboardsFixerOnDeploy")
                .onCreate(invokeOnCreate)
                .onUpdate(invokeOnUpdate)
                .policy(AwsCustomResourcePolicy.fromStatements(List.of(
                        PolicyStatement.Builder.create()
                                .effect(Effect.ALLOW)
                                .actions(List.of("lambda:InvokeFunction"))
                                .resources(List.of(dashboardsFixerLambda.getFunctionArn()))
                                .build()
                )))
                .build();

        // Bootstrap OpenSearch ingest pipeline and index template so dashboards work without manual steps
        Function ingestBootstrap = Function.Builder.create(this, "osdfwIngestBootstrap")
                .architecture(Architecture.ARM_64)
                .description("Bootstrap OpenSearch ingest pipeline and index template for WAF Dashboard")
                .handler("index.handler")
                .logRetention(RetentionDays.ONE_MONTH)
                .role(customizerRole)
                .code(Code.fromAsset("assets/os-bootstrap-lambda"))
                .runtime(Runtime.PYTHON_3_9)
                .memorySize(512)
                .timeout(Duration.minutes(15))
                .environment(Map.of(
                        "ES_ENDPOINT", props.getOpenSearchDomain().getDomainEndpoint(),
                        "REGION", this.getRegion(),
                        "FORCE_RESET", "false"
                ))
                .build();

        CustomResource.Builder.create(this, "osdfwIngestBootstrapper")
                .serviceToken(ingestBootstrap.getFunctionArn())
                .removalPolicy(RemovalPolicy.DESTROY)
                .properties(Map.of(
                        "StackName", this.getStackName(),
                        "Region", this.getRegion(),
                        "ForceNonce", String.valueOf(System.currentTimeMillis())
                ))
                .build();
    }

    private List<Rule> createEvents(Function targetLambdaFn) {
        
        Rule newACLForWafV2 = Rule.Builder.create(this, "osdfwCaptureNewAclsWafv2")
                .description("AWS WAF Dashboards Solution - detects new WebACLs and rules for WAFv2.")
                .eventPattern(EventPattern.builder()
                        .source(List.of("aws.wafv2"))
                        .detailType(List.of("AWS API Call via CloudTrail"))
                        .detail(Map.of(
                                "eventSource", List.of("wafv2.amazonaws.com"),
                                "eventName", List.of("CreateWebACL", "CreateRule")
                        ))
                        .build())
                .targets(List.of(LambdaFunction.Builder.create(targetLambdaFn).build()))
                .enabled(true)
                .build();

        // todo add conditional parameter to disable waf v1 capabilities
        Rule newACLRulesForWafRegional = Rule.Builder.create(this, "osdfwCaptureNewAclsWafv1Regional")
                .description("AWS WAF Dashboards Solution - detects new WebACLs and rules for WAF Regional.")
                .eventPattern(EventPattern.builder()
                        .source(List.of("aws.waf-regional"))
                        .detailType(List.of("AWS API Call via CloudTrail"))
                        .detail(Map.of(
                                "eventSource", List.of("waf.amazonaws.com"),
                                "eventName", List.of("CreateWebACL", "CreateRule")
                        ))
                        .build())
                .targets(List.of(LambdaFunction.Builder.create(targetLambdaFn).build()))
                .enabled(true)
                .build();

        Rule newACLRulesForWafGlobal = Rule.Builder.create(this, "osdfwCaptureNewAclsWafv1Global")
                .description("AWS WAF Dashboards Solution - detects new WebACLs and rules for WAF Global.")
                .eventPattern(EventPattern.builder()
                        .source(List.of("aws.waf"))
                        .detailType(List.of("AWS API Call via CloudTrail"))
                        .detail(Map.of(
                                "eventSource", List.of("waf-regional.amazonaws.com"),
                                "eventName", List.of("CreateWebACL", "CreateRule")
                        ))
                        .build())
                .targets(List.of(LambdaFunction.Builder.create(targetLambdaFn).build()))
                .enabled(true)
                .build();

        return List.of(newACLRulesForWafRegional, newACLRulesForWafGlobal, newACLForWafV2);
    }

    private Role createLambdaRole() {
        //todo too broad
        PolicyStatement policyStatement = PolicyStatement.Builder.create()
                .effect(Effect.ALLOW)
                .actions(List.of(
                        "es:*",
                        //"es:UpdateElasticsearchDomainConfig",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "events:PutRule",
                        "events:DeleteRule",
                        "lambda:AddPermission",
                        "events:PutTargets",
                        "events:RemoveTargets",
                        "lambda:RemovePermission",
                        "iam:PassRole",
                        "waf:ListWebACLs",
                        "waf-regional:ListWebACLs",
                        "waf:ListRules",
                        "waf-regional:ListRules",
                        "wafv2:ListWebACLs",
                        "s3:*"
                ))
                .resources(List.of("*"))
                .build();

        ManagedPolicy policy = ManagedPolicy.Builder.create(this, "osdfwCustomizerLambdaPolicy")
                .statements(List.of(policyStatement))
                .build();

        return Role.Builder.create(this, "osdfwCustomizerLambdaRole")
                .assumedBy(new ServicePrincipal("lambda.amazonaws.com"))
                .description("AWS WAF Dashboards Lambda role")
                .managedPolicies(List.of(policy))
                .build();

    }

    public void createCustomizer(Function dashboardsCustomizerLambda, StreamStackProps props) {
        CustomResource.Builder.create(this, "osdfwCustomResourceLambda")
                .serviceToken(dashboardsCustomizerLambda.getFunctionArn())
                .removalPolicy(RemovalPolicy.DESTROY)
                .properties(Map.of(
                        "StackName", this.getStackName(),
                        "Region", this.getRegion(),
                        "Host", props.getOpenSearchDomain().getDomainEndpoint(),
                        "AccountID", this.getAccount(),
                        "Nonce", String.valueOf(System.currentTimeMillis())
                ))
                .build();
    }
}
