#!/bin/sh

# This script was used in order to creat a gcloud project

export PROJECT_ID="detection-range-$(openssl rand -hex 3)"
gcloud projects create $PROJECT_ID
gcloud config set project $PROJECT_ID

# link billing in concsole or with command below
# gcloud billing projects link $PROJECT_ID --billing-account $BILLING_ACCOUNT_ID

gcloud auth application-default login