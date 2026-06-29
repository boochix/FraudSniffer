from fraudsniffer.models import FeatureStatus, ReasonCode
from fraudsniffer.semantic_checker import check_semantic_coherence, local_semantic_stub


def test_local_semantic_stub_is_offline_and_deterministic():
    fields = {
        "salary_amount": {"value": 150000, "status": FeatureStatus.REAL.value},
        "loan_amount": 20_000_000,
        "job_title": "Intern",
        "employer_name": "AB",
    }

    first = check_semantic_coherence(fields)
    second = check_semantic_coherence(fields)

    assert first == second
    assert first.source == "LOCAL_STUB"
    assert first.score >= 0.65
    assert first.reason_code == ReasonCode.SEMANTIC_INCOHERENCE.value


def test_semantic_stub_does_not_penalize_unavailable_fields():
    result = local_semantic_stub(
        {
            "salary_amount": {"value": None, "status": FeatureStatus.UNAVAILABLE.value},
            "employer_name": {"value": None, "status": FeatureStatus.UNAVAILABLE.value},
            "loan_amount": 2_000_000,
        }
    )

    assert result.source == "LOCAL_STUB"
    assert result.score < 0.2
    assert result.reason_code is None
    assert "Insufficient reliable fields" in result.rationale


def test_semantic_stub_flags_obvious_designation_salary_mismatch():
    result = local_semantic_stub(
        {
            "salary_amount": {"value": 475000, "status": FeatureStatus.REAL.value},
            "designation": {
                "value": "Junior Sales Executive",
                "status": FeatureStatus.REAL.value,
            },
            "employer_name": {
                "value": "SKYLINE INFRASTRUCTURE PRIVATE LIMITED",
                "status": FeatureStatus.REAL.value,
            },
        }
    )

    assert result.source == "LOCAL_STUB"
    assert result.score >= 0.65
    assert result.reason_code == ReasonCode.SEMANTIC_INCOHERENCE.value



