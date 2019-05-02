from __future__ import print_function

import base64
import gzip
import json
import os
import re
import boto3

# Imported through Lambda Layer
from datadog import datadog_lambda_wrapper, lambda_metric

# Pass custom tags as environment variable, ensure comma separated, no trailing comma in envvar!
DD_TAGS = os.environ.get("DD_TAGS", "")

class metric:
    def __init__(self):
        self.name = ""
        self.value = 0

@datadog_lambda_wrapper
def lambda_handler(event, context):
    try:
        metrics = awslogs_handler(event, context)
        for metric in metrics:
            for key in metric:
                lambda_metric(convert_snake_case(key.replace('-', '_')), metric[key], tags=[DD_TAGS])
    except Exception as e:
        print("Unexpected exception: {} for event {}".format(str(e), event))

# Handle CloudWatch logs
def awslogs_handler(event, context):
    # Get logs
    logs = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))

    # For Lambda logs we want to extract the function name,
    # then use it to generate custom metric name.
    # Start by splitting the log group to get the function name
    log_group_parts = logs["logGroup"].split("/lambda/")
    if len(log_group_parts) > 0:
        function_name = log_group_parts[1].lower()

    # Extract structured custom metric
    for log in logs["logEvents"]:
        if log['message'] and log['message'].startswith('REPORT RequestId:'):
            # Split message based on tabultations
            parts = log['message'].split('\t',5)
            metric = {
                function_name + "_billed_duration": re.findall("Billed Duration: (.*) ms", parts[2])[0],
                function_name + "_memory_used": re.findall("Max Memory Used: (.*) MB", parts[4])[0],
                function_name + "_memory_size": re.findall("Memory Size: (.*) MB", parts[3])[0]
            }
            yield metric

# Convert a name to snake case
def convert_snake_case(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()