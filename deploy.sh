#!/bin/bash
cd /Users/apple/Desktop/projects/aws-waf-dashboard

# Deploy with new domain names and stack name
cdk deploy \
  --parameters osdfwDashboardsAdminEmail=hamzaawanit@gmail.com \
  --parameters osdfwCognitoDomain=hamzawaf2025 \
  --parameters osdfwOsDomainName=osdfw-opensearch-domain-2025 \
  --require-approval never
