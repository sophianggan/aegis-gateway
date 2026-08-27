from uuid import UUID

from aegis.domain.models import Classification, DataField, Record


DEMO_RECORDS = (
    Record(
        id=UUID("11111111-1111-4111-8111-111111111111"),
        source="maintenance-ledger",
        fields={
            "asset": DataField(value="compressor-7", classification=Classification.INTERNAL),
            "status": DataField(value="inspection due", classification=Classification.INTERNAL),
            "site": DataField(
                value="north facility",
                classification=Classification.CONFIDENTIAL,
                compartments={"operations"},
            ),
            "access_code": DataField(
                value="NORTH-7391",
                classification=Classification.RESTRICTED,
                compartments={"physical-security"},
                exportable=False,
            ),
        },
    ),
    Record(
        id=UUID("22222222-2222-4222-8222-222222222222"),
        source="incident-register",
        fields={
            "summary": DataField(
                value="Temperature excursion resolved after sensor replacement",
                classification=Classification.INTERNAL,
            ),
            "owner": DataField(
                value="Reliability team",
                classification=Classification.CONFIDENTIAL,
                compartments={"operations"},
            ),
            "private_note": DataField(
                value="CASE-OMEGA-4815",
                classification=Classification.RESTRICTED,
                compartments={"investigations"},
            ),
        },
    ),
)

