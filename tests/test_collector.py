import unittest
from unittest.mock import Mock
from cloudpath_guard.collector import collect
from cloudpath_guard.demo import snapshot, ROLE, PROFILE


class CollectorTests(unittest.TestCase):
    def session(self):
        data = snapshot()
        ec2, iam, sts = Mock(), Mock(), Mock()
        sts.get_caller_identity.return_value = {"Account": data["account"]}
        responses = {
            "describe_instances": [{"Reservations": [{"Instances": data["instances"]}]}],
            "describe_security_groups": [{"SecurityGroups": data["security_groups"]}],
            "describe_route_tables": [{"RouteTables": data["route_tables"]}],
            "list_role_policies": [{"PolicyNames": ["inline"]}],
            "list_attached_role_policies": [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/demo"}]}],
        }
        def paginator(operation):
            obj = Mock()
            obj.paginate.return_value = responses[operation]
            return obj
        ec2.get_paginator.side_effect = paginator
        iam.get_paginator.side_effect = paginator
        iam.get_instance_profile.return_value = {"InstanceProfile": {"Roles": [{"Arn": ROLE, "RoleName": "demo-web-role"}]}}
        iam.get_role.return_value = {"Role": {}}
        iam.get_role_policy.return_value = {"PolicyDocument": data["roles"][ROLE]["policy_documents"][0]}
        iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v2"}}
        iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": []}}}
        session = Mock()
        session.client.side_effect = lambda service, **kw: {"ec2": ec2, "iam": iam, "sts": sts}[service]
        return session, ec2, iam

    def test_complete_paginated_capture(self):
        session, ec2, iam = self.session()
        result = collect("us-east-1", session=session)
        self.assertTrue(result["collection_complete"])
        self.assertEqual(result["profiles"][PROFILE], [ROLE])
        self.assertEqual(len(result["roles"][ROLE]["policy_documents"]), 2)
        iam.get_policy_version.assert_called_once_with(PolicyArn="arn:aws:iam::aws:policy/demo", VersionId="v2")

    def test_api_failure_retained_and_incomplete(self):
        session, ec2, iam = self.session()
        class Denied(Exception):
            response = {"Error": {"Code": "AccessDenied"}}
        iam.get_role_policy.side_effect = Denied("sensitive raw message")
        result = collect("us-east-1", session=session)
        self.assertFalse(result["collection_complete"])
        self.assertEqual(result["errors"], [{"operation": "get_role_policy", "code": "AccessDenied"}])


if __name__ == "__main__":
    unittest.main()
