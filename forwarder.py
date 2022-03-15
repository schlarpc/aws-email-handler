import inspect

from awacs import logs, s3, ses, sts
from awacs.aws import Allow, PolicyDocument, Principal, Statement
from troposphere import (
    AccountId,
    And,
    Equals,
    If,
    ImportValue,
    Join,
    Not,
    Parameter,
    Select,
    Split,
    Template,
)
from troposphere.awslambda import Code, Environment, Function, Permission
from troposphere.events import Rule, Target
from troposphere.iam import PolicyType, Role
from troposphere.logs import LogGroup


def resolve_importable_parameter(template, parameter):
    condition = template.add_condition(
        f"{parameter.title}RequiresImport",
        And(
            Not(Equals(parameter.ref(), "")),
            Equals(Select(0, Split("$", parameter.ref())), ""),
        ),
    )

    return If(
        condition,
        ImportValue(Select(1, Split("$", parameter.ref()))),
        parameter.ref(),
    )


def handler(event, context):
    import email.headerregistry
    import email.message
    import email.parser
    import email.policy
    import json
    import os

    import boto3

    print(json.dumps(event["detail"]["s3"]))

    s3 = boto3.client("s3")
    ses = boto3.client("ses")

    response = s3.get_object(
        Bucket=event["detail"]["s3"]["bucket"],
        Key=event["detail"]["s3"]["key"],
    )

    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        response["Body"].read()
    )

    if "Reply-To" not in message:
        message.add_header(
            "Reply-To",
            message["From"],
        )
    message.replace_header(
        "From",
        email.headerregistry.Address(
            display_name=str(message["From"]),
            username="noreply",
            domain=event["detail"]["receipt"]["recipients"][0].split("@")[-1],
        ),
    )
    message.replace_header(
        "To",
        os.environ["DESTINATION_EMAIL_ADDRESS"],
    )
    for bad_header in ("Return-Path", "CC", "BCC"):
        del message[bad_header]

    response = ses.send_raw_email(
        RawMessage={"Data": message.as_bytes(policy=email.policy.SMTP)},
    )


def create_template():
    template = Template(Description="SES email forwarder")

    destination_email_address = template.add_parameter(
        Parameter(
            "DestinationEmailAddress",
            Type="String",
        )
    )

    parameter_event_bus_name = template.add_parameter(
        Parameter(
            "EventBusName",
            Type="String",
        )
    )

    parameter_bucket_arn = template.add_parameter(
        Parameter(
            "BucketArn",
            Type="String",
        )
    )

    event_bus_name = resolve_importable_parameter(template, parameter_event_bus_name)

    bucket_arn = resolve_importable_parameter(template, parameter_bucket_arn)

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
                    "DESTINATION_EMAIL_ADDRESS": destination_email_address.ref()
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
                        Action=[s3.GetObject],
                        Resource=[Join("/", [bucket_arn, "*"])],
                    ),
                    Statement(
                        Effect=Allow,
                        Action=[ses.SendRawEmail],
                        Resource=["*"],
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
            Principal="events.amazonaws.com",
            SourceAccount=AccountId,
            DependsOn=[function_policy],
        )
    )

    rule = template.add_resource(
        Rule(
            "Rule",
            EventBusName=event_bus_name,
            EventPattern={
                "source": ["ses"],
                "detail-type": ["Mail Received"],
            },
            Targets=[
                Target(
                    Id="default",
                    Arn=function.get_att("Arn"),
                )
            ],
            DependsOn=[function_permission],
        )
    )

    return template


if __name__ == "__main__":
    print(create_template().to_json())
