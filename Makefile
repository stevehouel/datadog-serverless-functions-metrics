
AWS_REGION = eu-west-1

S3_BUCKET ?= <your-bucket-name>
DATADOG_API_KEY ?= <your-datadog-api-key>
DATADOG_APP_KEY ?= <your-datadog-app-key>

CFN_PARAMS := DataDogApiKey=$(DATADOG_API_KEY) \
		DataDogAppKey=$(DATADOG_APP_KEY)

package:
	sam package \
	--template-file dd-lambda-metrics-template.yml \
	--s3-bucket $(S3_BUCKET) \
	--s3-prefix datadog-serverless-functions-metrics \
	--output-template-file template-out.yml \
	--region $(AWS_REGION)

deploy:
	sam deploy \
	--template-file template-out.yml \
	--stack-name datadog-custom-metrics \
	--capabilities CAPABILITY_IAM \
	--parameter-overrides $(CFN_PARAMS) \
	--region $(AWS_REGION)