# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2018 Datadog, Inc.

from __future__ import print_function

import base64
import gzip
import json
import os
import re
import socket
import ssl
import urllib
from io import BytesIO, BufferedReader

import boto3

# Proxy
# Define the proxy endpoint to forward the logs to
DD_SITE = os.getenv("DD_SITE", default="datadoghq.com")
DD_URL = os.getenv("DD_URL", default="lambda-intake.logs." + DD_SITE)

# Define the proxy port to forward the logs to
try:
    if "DD_SITE" in os.environ and DD_SITE == "datadoghq.eu":
        DD_PORT = int(os.environ.get("DD_PORT", 443))
    else:
        DD_PORT = int(os.environ.get("DD_PORT", 10516))
except Exception:
    DD_PORT = 10516

# Scrubbing sensitive data
# Option to redact all pattern that looks like an ip address / email address
try:
    is_ipscrubbing = os.environ["REDACT_IP"]
except Exception:
    is_ipscrubbing = False
try:
    is_emailscrubbing = os.environ["REDACT_EMAIL"]
except Exception:
    is_emailscrubbing = False

# DD_API_KEY: Datadog API Key
DD_API_KEY = "<your_api_key>"
if "DD_KMS_API_KEY" in os.environ:
    ENCRYPTED = os.environ["DD_KMS_API_KEY"]
    DD_API_KEY = boto3.client("kms").decrypt(
        CiphertextBlob=base64.b64decode(ENCRYPTED)
    )["Plaintext"]
elif "DD_API_KEY" in os.environ:
    DD_API_KEY = os.environ["DD_API_KEY"]

# Strip any trailing and leading whitespace from the API key
DD_API_KEY = DD_API_KEY.strip()

cloudtrail_regex = re.compile(
    "\d+_CloudTrail_\w{2}-\w{4,9}-\d_\d{8}T\d{4}Z.+.json.gz$", re.I
)
ip_regex = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
email_regex = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.I)

DD_SOURCE = "ddsource"
DD_CUSTOM_TAGS = "ddtags"
DD_SERVICE = "service"
DD_HOST = "host"
DD_FORWARDER_VERSION = "1.2.3"

# Pass custom tags as environment variable, ensure comma separated, no trailing comma in envvar!
DD_TAGS = os.environ.get("DD_TAGS", "")

class DatadogConnection(object):
    def __init__(self, host, port, ddApiKey):
        self.host = host
        self.port = port
        self.api_key = ddApiKey
        self._sock = None

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = ssl.wrap_socket(s)
        s.connect((self.host, self.port))
        return s

    def safe_submit_log(self, log, metadata):
        try:
            self.send_entry(log, metadata)
        except Exception as e:
            # retry once
            if self._sock:
                # make sure we don't keep old connections open
                self._sock.close()
            self._sock = self._connect()
            self.send_entry(log, metadata)
        return self

    def send_entry(self, log_entry, metadata):
        # The log_entry can only be a string or a dict
        if isinstance(log_entry, str):
            log_entry = {"message": log_entry}
        elif not isinstance(log_entry, dict):
            raise Exception(
                "Cannot send the entry as it must be either a string or a dict. Provided entry: "
                + str(log_entry)
            )

        # Merge with metadata
        log_entry = merge_dicts(log_entry, metadata)

        # Send to Datadog
        str_entry = json.dumps(log_entry)

        # Scrub ip addresses if activated
        if is_ipscrubbing:
            try:
                str_entry = ip_regex.sub("xxx.xxx.xxx.xx", str_entry)
            except Exception as e:
                print(
                    "Unexpected exception while scrubbing logs: {} for event {}".format(
                        str(e), str_entry
                    )
                )
        # Scrub email addresses if activated
        if is_emailscrubbing:
            try:
                str_entry = email_regex.sub("xxxxx@xxxxx.com", str_entry)
            except Exception as e:
                print(
                    "Unexpected exception while scrubbing logs: {} for event {}".format(
                        str(e), str_entry
                    )
                )

        # For debugging purpose uncomment the following line
        # print(str_entry)
        prefix = "%s " % self.api_key
        return self._sock.send((prefix + str_entry + "\n").encode("UTF-8"))

    def __enter__(self):
        self._sock = self._connect()
        return self

    def __exit__(self, ex_type, ex_value, traceback):
        if self._sock:
            self._sock.close()
        if ex_type is not None:
            print("DatadogConnection exit: ", ex_type, ex_value, traceback)


def lambda_handler(event, context):
    # Check prerequisites
    if DD_API_KEY == "<your_api_key>" or DD_API_KEY == "":
        raise Exception(
            "You must configure your API key before starting this lambda function (see #Parameters section)"
        )
    # Check if the API key is the correct number of characters
    if len(DD_API_KEY) != 32:
        raise Exception(
            "The API key is not the expected length. Please confirm that your API key is correct"
        )

    metadata = {"ddsourcecategory": "aws"}

    # create socket
    with DatadogConnection(DD_URL, DD_PORT, DD_API_KEY) as con:
        # Add the context to meta
        if "aws" not in metadata:
            metadata["aws"] = {}
        aws_meta = metadata["aws"]
        aws_meta["function_version"] = context.function_version
        aws_meta["invoked_function_arn"] = context.invoked_function_arn

        # Add custom tags here by adding new value with the following format "key1:value1, key2:value2"  - might be subject to modifications
        dd_custom_tags_data = {
            "forwardername": context.function_name.lower(),
            "memorysize": context.memory_limit_in_mb,
            "forwarder_version": DD_FORWARDER_VERSION,
        }
        metadata[DD_CUSTOM_TAGS] = ",".join(
            filter(
                None,
                [
                    DD_TAGS,
                    ",".join(
                        [
                            "{}:{}".format(k, v)
                            for k, v in dd_custom_tags_data.iteritems()
                        ]
                    ),
                ],
            )
        )

        try:
            logs = awslogs_handler(event, context, metadata)
            for log in logs:
                con = con.safe_submit_log(log, metadata)
        except Exception as e:
            print("Unexpected exception: {} for event {}".format(str(e), event))

# Utility functions
# Handle CloudWatch logs
def awslogs_handler(event, context, metadata):
    # Get logs
    with gzip.GzipFile(
        fileobj=BytesIO(base64.b64decode(event["awslogs"]["data"]))
    ) as decompress_stream:
        # Reading line by line avoid a bug where gzip would take a very long
        # time (>5min) for file around 60MB gzipped
        data = "".join(BufferedReader(decompress_stream))
    logs = json.loads(str(data))

    # Set the source on the logs
    source = logs.get("logGroup", "cloudwatch")
    metadata[DD_SOURCE] = parse_event_source(event, source)

    # Default service to source value
    metadata[DD_SERVICE] = metadata[DD_SOURCE]

    # Build aws attributes
    aws_attributes = {
        "aws": {
            "awslogs": {
                "logGroup": logs["logGroup"],
                "logStream": logs["logStream"],
                "owner": logs["owner"],
            }
        }
    }

    # For Lambda logs we want to extract the function name,
    # then rebuild the arn of the monitored lambda using that name.
    # Start by splitting the log group to get the function name
    log_group_parts = logs["logGroup"].split("/lambda/")
    if len(log_group_parts) > 0:
        function_name = log_group_parts[1].lower()
        # Split the arn of the forwarder to extract the prefix
        arn_parts = context.invoked_function_arn.split("function:")
        if len(arn_parts) > 0:
            arn_prefix = arn_parts[0]
            # Rebuild the arn by replacing the function name
            arn = arn_prefix + "function:" + function_name
            # Add the arn as a log attribute
            arn_attributes = {"lambda": {"arn": arn}}
            aws_attributes = merge_dicts(aws_attributes, arn_attributes)
            # Add the function name as tag
            metadata[DD_CUSTOM_TAGS] += ",functionname:" + function_name
            # Set the arn as the hostname
            metadata[DD_HOST] = arn

    # Create and send structured logs to Datadog
    for log in logs["logEvents"]:
        yield merge_dicts(log, aws_attributes)

def merge_dicts(a, b, path=None):
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                raise Exception(
                    "Conflict while merging metadatas and the log entry at %s"
                    % ".".join(path + [str(key)])
                )
        else:
            a[key] = b[key]
    return a