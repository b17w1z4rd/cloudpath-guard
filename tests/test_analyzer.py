import unittest
from cloudpath_guard.analyzer import analyze, broad_grants, internet_route
from cloudpath_guard.demo import snapshot, hardened, ROLE


class AnalyzerTests(unittest.TestCase):
    def test_demo_chain(self):
        report = analyze(snapshot())
        self.assertEqual({f["rule"] for f in report["findings"]}, {"CP001", "CP002", "CP003", "CP004"})
        self.assertTrue(report["collection_complete"])
        chain = next(f for f in report["findings"] if f["rule"] == "CP004")
        self.assertEqual(chain["evidence"]["exploitability"], "not_established")

    def test_hardening_and_drift(self):
        before = analyze(snapshot())
        after = analyze(hardened(), before)
        self.assertEqual({f["rule"] for f in after["findings"]}, {"CP001"})
        self.assertEqual(len(after["drift"]["no_longer_observed"]), 3)
        self.assertEqual(len(after["drift"]["changed"]), 1)

    def test_private_or_nat_no_direct_internet(self):
        data = snapshot()
        data["route_tables"][0]["Routes"][0]["GatewayId"] = "nat-123"
        rules = {f["rule"] for f in analyze(data)["findings"]}
        self.assertNotIn("CP001", rules)
        self.assertNotIn("CP004", rules)

    def test_explicit_subnet_route_overrides_main(self):
        data = snapshot()
        data["route_tables"].append({"RouteTableId": "rtb-private", "VpcId": "vpc-demo",
                                     "Associations": [{"SubnetId": "subnet-demo"}], "Routes": []})
        self.assertIsNone(internet_route(data["instances"][0], data["route_tables"]))

    def test_global_explicit_deny_overrides(self):
        role = {"policy_documents": [{"Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}]}]}
        self.assertEqual(broad_grants(role), [])

    def test_conditional_deny_and_boundary_are_visible(self):
        role = {"permissions_boundary": {"PermissionsBoundaryArn": "demo"}, "policy_documents": [{"Statement": [
            {"Effect": "Allow", "Action": "IAM:PASSROLE", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*", "Condition": {"Bool": {"x": "false"}}}]}]}
        result = broad_grants(role)
        self.assertTrue(result[0]["conditions_or_unmodeled_statements"])
        self.assertTrue(result[0]["boundary_present"])

    def test_scoped_resource_not_called_broad(self):
        self.assertEqual(broad_grants(hardened()["roles"][ROLE]), [])

    def test_missing_profile_prevents_complete_result(self):
        data = snapshot()
        data["profiles"] = {}
        result = analyze(data)
        self.assertFalse(result["collection_complete"])
        self.assertTrue(result["warnings"])

    def test_partial_snapshot_does_not_assert_remediation(self):
        data = hardened()
        data["errors"] = [{"operation": "get_policy", "code": "AccessDenied"}]
        data["collection_complete"] = False
        result = analyze(data, analyze(snapshot()))
        self.assertFalse(result["drift"]["comparison_complete"])

    def test_wrong_account_baseline_rejected(self):
        baseline = analyze(snapshot())
        baseline["account"] = "444455556666"
        with self.assertRaises(ValueError):
            analyze(snapshot(), baseline)

    def test_imds_disabled_no_metadata_finding(self):
        data = snapshot()
        data["instances"][0]["MetadataOptions"]["HttpEndpoint"] = "disabled"
        self.assertNotIn("CP002", {f["rule"] for f in analyze(data)["findings"]})

    def test_stable_ids_ignore_timestamp(self):
        data = snapshot()
        before = analyze(data)
        data["collected_at"] = "2026-03-01T00:00:00Z"
        after = analyze(data, before)
        self.assertEqual(len(after["drift"]["unchanged"]), 4)


if __name__ == "__main__":
    unittest.main()
