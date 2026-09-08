from opencra_api.orm import CraCase, Organization, Product
from opencra_api.srp import PortalOnlyAdapter, build_packet
from opencra_api.srp.adapter import SrpSubmission


def test_portal_adapter_never_submits() -> None:
    result = PortalOnlyAdapter().submit(
        SrpSubmission(stage="early_warning", fields={}, markdown="")
    )
    assert result.submitted is False
    assert "no public API" in result.message


def test_srp_packet_contains_disclaimer() -> None:
    org = Organization(id="o", name="Acme", slug="acme", main_establishment_ms="DE")
    product = Product(id="p", org_id="o", name="Widget", version="1.0", market_member_states=["DE", "FR"])
    case = CraCase(
        id="c",
        org_id="o",
        product_id="p",
        case_type="actively_exploited_vuln",
        status="candidate",
    )
    packet = build_packet(org, product, case, "early_warning")
    assert "does not file with ENISA" in packet.fields["disclaimer"]
    assert "Widget" in packet.markdown
