from __future__ import annotations

RESULT_ARTIFACT_ROUTE = "/artifacts/{result_ref}"


def result_artifact_uri(public_base_url: str, reference: str) -> str:
    path = RESULT_ARTIFACT_ROUTE.replace("{result_ref}", reference)
    return public_base_url.rstrip("/") + path
