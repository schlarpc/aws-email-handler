"""
Manual steps:
* Set receipt rule set as "Active"
* Verify domains in SES
* Configure domain's MX record
"""

import inspect

from awacs import events, logs, s3, sts
from awacs.aws import (
    Allow,
    Condition,
    PolicyDocument,
    Principal,
    Statement,
    StringEquals,
)
from troposphere import (
    AccountId,
    Export,
    Join,
    Output,
    Region,
    Select,
    Split,
    StackId,
    StackName,
    Template,
    URLSuffix,
)
from troposphere.awslambda import Code, Environment, Function, Permission
from troposphere.events import EventBus
from troposphere.eventschemas import Discoverer
from troposphere.iam import PolicyType, Role
from troposphere.logs import LogGroup
from troposphere.s3 import (
    AbortIncompleteMultipartUpload,
    Bucket,
    BucketEncryption,
    BucketPolicy,
    LifecycleConfiguration,
    LifecycleRule,
    LifecycleRuleTransition,
    OwnershipControls,
    OwnershipControlsRule,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.ses import (
    Action,
    LambdaAction,
    ReceiptRule,
    ReceiptRuleSet,
    Rule,
    S3Action,
)


def handler(event, context):
    import json
    import os

    import boto3

    events = boto3.client("events")

    for record in event["Records"]:
        details = record["ses"]
        events.put_events(
            Entries=[
                {
                    "EventBusName": os.environ["EVENT_BUS_NAME"],
                    "Source": "ses",
                    "DetailType": "Mail Received",
                    "Time": details["receipt"]["timestamp"],
                    "Detail": json.dumps(
                        {
                            **details,
                            "s3": {
                                "bucket": os.environ["S3_BUCKET_NAME"],
                                "key": details["mail"]["messageId"],
                            },
                        }
                    ),
                }
            ]
        )


def create_template():
    template = Template(Description="SES inbound mail handler")

    bucket = template.add_resource(
        Bucket(
            "Bucket",
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    LifecycleRule(
                        Transitions=[
                            LifecycleRuleTransition(
                                StorageClass="INTELLIGENT_TIERING",
                                TransitionInDays=1,
                            ),
                        ],
                        Status="Enabled",
                    ),
                    LifecycleRule(
                        AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                            DaysAfterInitiation=1,
                        ),
                        Status="Enabled",
                    ),
                ]
            ),
            BucketEncryption=BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                            SSEAlgorithm="AES256"
                        )
                    )
                ]
            ),
            OwnershipControls=OwnershipControls(
                Rules=[OwnershipControlsRule(ObjectOwnership="BucketOwnerEnforced")],
            ),
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
        )
    )

    bucket_policy = template.add_resource(
        BucketPolicy(
            "BucketPolicy",
            Bucket=bucket.ref(),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "ses.amazonaws.com"),
                        Action=[s3.PutObject],
                        Resource=[Join("/", [bucket.get_att("Arn"), "*"])],
                        Condition=Condition(
                            StringEquals(
                                {
                                    "aws:SourceAccount": AccountId,
                                }
                            )
                        ),
                    ),
                ],
            ),
        )
    )

    event_bus = template.add_resource(
        EventBus(
            "EventBus",
            Name=Join("-", [StackName, Select(2, Split("/", StackId))]),
        )
    )

    event_bus_discoverer = template.add_resource(
        Discoverer(
            "EventBusDiscoverer",
            SourceArn=event_bus.get_att("Arn"),
        )
    )

    function_role = template.add_resource(
        Role(
            "FunctionRole",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    ),
                ],
            ),
        )
    )

    function = template.add_resource(
        Function(
            "Function",
            Role=function_role.get_att("Arn"),
            Runtime="python3.9",
            Code=Code(ZipFile=inspect.getsource(handler)),
            Handler="index.handler",
            MemorySize=256,
            Environment=Environment(
                Variables={
                    "EVENT_BUS_NAME": event_bus.ref(),
                    "S3_BUCKET_NAME": bucket.ref(),
                },
            ),
        )
    )

    function_log_group = template.add_resource(
        LogGroup(
            "FunctionLogGroup",
            LogGroupName=Join("/", ["/aws/lambda", function.ref()]),
            RetentionInDays=30,
        )
    )

    function_policy = template.add_resource(
        PolicyType(
            "FunctionPolicy",
            PolicyName=function.ref(),
            PolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[function_log_group.get_att("Arn")],
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[events.PutEvents],
                        Resource=[event_bus.get_att("Arn")],
                    ),
                ],
            ),
            Roles=[function_role.ref()],
        )
    )

    function_permission = template.add_resource(
        Permission(
            "FunctionPermission",
            Action="lambda:InvokeFunction",
            FunctionName=function.get_att("Arn"),
            Principal="ses.amazonaws.com",
            SourceAccount=AccountId,
            DependsOn=[function_policy],
        )
    )

    receipt_rule_set = template.add_resource(
        ReceiptRuleSet(
            "ReceiptRuleSet",
        )
    )

    receipt_rule = template.add_resource(
        ReceiptRule(
            "ReceiptRule",
            RuleSetName=receipt_rule_set.ref(),
            Rule=Rule(
                Enabled=True,
                ScanEnabled=True,
                TlsPolicy="Optional",
                Actions=[
                    Action(
                        S3Action=S3Action(
                            BucketName=bucket.ref(),
                        ),
                    ),
                    Action(
                        LambdaAction=LambdaAction(
                            FunctionArn=function.get_att("Arn"),
                            InvocationType="Event",
                        ),
                    ),
                ],
            ),
            DependsOn=[bucket_policy, function_permission],
        )
    )

    template.add_output(
        Output(
            "BucketArn",
            Value=bucket.get_att("Arn"),
            Export=Export(Join("-", [StackName, "BucketArn"])),
        )
    )

    template.add_output(
        Output(
            "EventBusName",
            Value=event_bus.ref(),
            Export=Export(Join("-", [StackName, "EventBusName"])),
        )
    )

    template.add_output(
        Output(
            "ReceiptRuleSetName",
            Value=receipt_rule_set.ref(),
            Export=Export(Join("-", [StackName, "ReceiptRuleSetName"])),
        )
    )

    template.add_output(
        Output(
            "MXDomainName",
            Value=Join(".", ["inbound-smtp", Region, URLSuffix]),
            Export=Export(Join("-", [StackName, "MXDomainName"])),
        )
    )

    return template


if __name__ == "__main__":
    print(create_template().to_json())
