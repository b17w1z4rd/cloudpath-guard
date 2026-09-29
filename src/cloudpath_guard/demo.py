import copy

ROLE = "arn:aws:iam::111122223333:role/demo-web-role"
PROFILE = "arn:aws:iam::111122223333:instance-profile/demo-web-profile"


def snapshot():
    return {"schema_version": 1, "account": "111122223333", "region": "us-east-1",
            "collected_at": "2026-01-01T00:00:00+00:00", "collection_complete": True, "errors": [],
            "instances": [{"InstanceId": "i-demo-web", "State": {"Name": "running"},
                           "VpcId": "vpc-demo", "SubnetId": "subnet-demo", "PublicIpAddress": "203.0.113.10",
                           "SecurityGroups": [{"GroupId": "sg-demo"}],
                           "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "optional"},
                           "IamInstanceProfile": {"Arn": PROFILE}}],
            "security_groups": [{"GroupId": "sg-demo", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
            "route_tables": [{"RouteTableId": "rtb-demo", "VpcId": "vpc-demo",
                              "Associations": [{"Main": True}],
                              "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-demo", "State": "active"}]}],
            "profiles": {PROFILE: [ROLE]}, "roles": {ROLE: {"permissions_boundary": None,
                "policy_documents": [{"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole"], "Resource": "*"}]}]}}}


def hardened():
    result = copy.deepcopy(snapshot())
    result["collected_at"] = "2026-01-02T00:00:00+00:00"
    result["instances"][0]["MetadataOptions"]["HttpTokens"] = "required"
    result["security_groups"][0]["IpPermissions"][0]["IpRanges"][0]["CidrIp"] = "10.0.0.0/8"
    result["roles"][ROLE]["policy_documents"][0]["Statement"][0] = {
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo-static-assets/*"}
    return result
