"""
tests/unit/test_enterprise.py — Unit tests for enterprise router models and policy logic.
"""

from deployguard.api.routers.enterprise import (
    DeployRequest,
    MergeRequest,
    PolicySettings,
)


def test_policy_defaults():
    policy = PolicySettings()
    assert policy.organization_name == "DeployGuard Enterprise"
    assert policy.max_auto_merge_score == 35
    assert policy.block_on_p0_sla is True
    assert policy.require_canary_for_medium_risk is True


def test_policy_custom_thresholds():
    custom = PolicySettings(
        organization_name="Acme Global Platform",
        max_auto_merge_score=50,
        block_on_p0_sla=False,
    )
    assert custom.organization_name == "Acme Global Platform"
    assert custom.max_auto_merge_score == 50
    assert custom.block_on_p0_sla is False


def test_merge_request_model():
    req = MergeRequest(merge_method="squash", operator="Sarah Lead")
    assert req.merge_method == "squash"
    assert req.override is False
    assert req.operator == "Sarah Lead"

    override_req = MergeRequest(
        merge_method="rebase",
        override=True,
        override_reason="Hotfix approved by VP",
    )
    assert override_req.override is True
    assert override_req.override_reason == "Hotfix approved by VP"


def test_deploy_request_model():
    deploy = DeployRequest(environment="canary", strategy="CANARY", traffic_percent=10)
    assert deploy.environment == "canary"
    assert deploy.strategy == "CANARY"
    assert deploy.traffic_percent == 10
