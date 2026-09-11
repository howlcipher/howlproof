"""Live adversaries against a running artifact.

These checks need the artifact up. When it is not up, they say so: a service that
would not start is an unavailable surface, never an absent problem.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib.parse import urlsplit

from howlproof.model import (
    Adversary,
    Confidence,
    Mode,
    Reproduction,
    ReproductionStep,
    Severity,
)
from howlproof.registry import Context, Evaluator, Outcome
from howlproof.service import request

#: Responses that leak implementation internals to a caller who sent bad input.
LEAK_MARKERS = (
    "Traceback (most recent call last)",
    "panic: ",
    "goroutine ",
    "at Object.",
    '\n  File "',
    "SQLSTATE",
    "ORA-0",
)


class _LiveEvaluator(Evaluator):
    """Shared applicability: a declared service that actually came up."""

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.service is None:
            return False, "the artifact declares no service, so there is nothing to reach"
        return True, ""

    def offline(self, context: Context):
        if not context.service_running:
            note = next(
                (n for n in context.notes if "service" in n or "in use" in n),
                "the declared service did not start",
            )
            return self.unavailable(note)
        return None


class HttpAuthorization(_LiveEvaluator):
    """Send requests the artifact is documented to refuse, and check that it refuses."""

    id = "http.authz"
    adversary = Adversary.SECURITY

    def applicable(self, context: Context) -> tuple[bool, str]:
        applicable, reason = super().applicable(context)
        if not applicable:
            return applicable, reason
        if not (context.config.api and context.config.api.authority_probes):
            return False, "the artifact declares no authorization boundaries to probe"
        return True, ""

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        assert context.config.api is not None
        checks, findings = [], []
        for probe in context.config.api.authority_probes:
            transcript: list[dict[str, Any]] = []
            for step in probe.setup:
                response = request(
                    context.service_base_url,
                    str(step.get("method", "POST")),
                    str(step.get("path", "/")),
                    body=step.get("body", {}),
                )
                transcript.append({"setup": step, "response": response.to_dict()})
            response = request(context.service_base_url, probe.method, probe.path, body=probe.body)
            transcript.append(
                {"probe": probe.model_dump(mode="json"), "response": response.to_dict()}
            )
            ref = context.save_evidence_json(self.id, f"{probe.name}.json", transcript)
            limitation = (
                "one authored request against a locally started instance; it does not "
                "enumerate every path to the same authority"
            )
            denied = response.status == probe.expect_status and (
                not probe.expect_body_contains or probe.expect_body_contains in response.body
            )
            if response.error:
                checks.append(
                    self.unavailable(
                        f"{probe.name}: the request did not complete ({response.error})",
                        suffix=probe.name,
                    )
                )
                continue
            if denied:
                checks.append(
                    self.verified(
                        f"{probe.name}: refused with {response.status} as documented",
                        limitation,
                        suffix=probe.name,
                        evidence_refs=[ref],
                    )
                )
                continue
            checks.append(
                self.failed(
                    f"{probe.name}: expected {probe.expect_status}, observed {response.status}",
                    limitation,
                    suffix=probe.name,
                    evidence_refs=[ref],
                    detail={"observed_status": response.status},
                )
            )
            findings.append(
                self.finding(
                    title=f"Authorization boundary not enforced: {probe.name}",
                    category="security",
                    severity=Severity.BLOCKER,
                    confidence=Confidence.CONFIRMED,
                    summary=(
                        f"{probe.description or probe.name}. The artifact answered "
                        f"{response.status} where {probe.expect_status} was required."
                    ),
                    evidence=json.dumps(transcript[-1], indent=2)[:4000],
                    remediation=(
                        "Derive authority on every request rather than trusting prior state, "
                        "and deny by default when the envelope is absent, expired or out of "
                        "scope."
                    ),
                    location=probe.path,
                    rule=f"http.authz.{probe.name}",
                    suffix=probe.name,
                    reproduction=Reproduction(
                        summary=f"Replay {probe.name} against a locally started instance.",
                        requires_service=True,
                        steps=[
                            ReproductionStep(
                                description=f"{step.get('method', 'POST')} {step.get('path')}",
                                kind="http_request",
                                payload={
                                    "method": step.get("method", "POST"),
                                    "path": step.get("path", "/"),
                                    "body": step.get("body", {}),
                                },
                                expect={},
                            )
                            for step in probe.setup
                        ]
                        + [
                            ReproductionStep(
                                description=f"{probe.method} {probe.path} must be refused",
                                kind="http_request",
                                payload={
                                    "method": probe.method,
                                    "path": probe.path,
                                    "body": probe.body,
                                },
                                expect={"status_not": probe.expect_status},
                            )
                        ],
                    ),
                )
            )
        return Outcome(checks=checks, findings=findings)


class HttpAbuse(_LiveEvaluator):
    """Malformed, oversized and unexpected requests must fail cleanly and leave it alive."""

    id = "http.abuse"
    adversary = Adversary.FUNCTIONAL

    def applicable(self, context: Context) -> tuple[bool, str]:
        applicable, reason = super().applicable(context)
        if not applicable:
            return applicable, reason
        if not (context.config.api and context.config.api.endpoints):
            return False, "the artifact declares no API endpoints to abuse"
        return True, ""

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        assert context.config.api is not None
        endpoint = context.config.api.endpoints[0]
        base = context.service_base_url
        cases = [
            (
                "malformed_json",
                {"raw_body": b"{not json at all", "content_type": "application/json"},
            ),
            ("empty_body", {"raw_body": b"", "content_type": "application/json"}),
            ("wrong_content_type", {"raw_body": b"id=1", "content_type": "text/plain"}),
            (
                "array_instead_of_object",
                {"raw_body": b"[1,2,3]", "content_type": "application/json"},
            ),
            ("null_body", {"raw_body": b"null", "content_type": "application/json"}),
            (
                "deep_nesting",
                {
                    "raw_body": ("[" * 200 + "]" * 200).encode(),
                    "content_type": "application/json",
                },
            ),
            (
                "oversized_body",
                {
                    "raw_body": json.dumps({"id": "a" * 200_000}).encode(),
                    "content_type": "application/json",
                },
            ),
        ]
        transcript: list[dict[str, Any]] = []
        leaks: list[str] = []
        crashes: list[str] = []
        for name, payload in cases:
            response = request(base, "POST", endpoint, **payload)  # type: ignore[arg-type]
            transcript.append({"case": name, "response": response.to_dict()})
            if response.error:
                crashes.append(f"{name}: {response.error}")
                continue
            if any(marker in response.body for marker in LEAK_MARKERS):
                leaks.append(name)

        alive = request(base, "POST", endpoint, body={})
        transcript.append({"case": "liveness_after_abuse", "response": alive.to_dict()})
        unknown_route = request(base, "POST", "/api/definitely-not-a-route", body={})
        transcript.append({"case": "unknown_route", "response": unknown_route.to_dict()})

        ref = context.save_evidence_json(self.id, "abuse.json", transcript)
        limitation = (
            "a fixed catalogue of malformed requests against one endpoint; it is not a fuzzing "
            "campaign and does not enumerate the artifact's whole input space"
        )
        findings = []
        if crashes:
            findings.append(
                self.finding(
                    title="The service drops connections on malformed input",
                    category="correctness",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    summary=(
                        "Requests with malformed bodies did not receive an HTTP response: "
                        + "; ".join(crashes[:5])
                    ),
                    evidence=json.dumps(transcript[:3], indent=2)[:4000],
                    remediation="Return a bounded 4xx for unparsable input instead of failing "
                    "the connection.",
                    location=endpoint,
                    rule="http.abuse.connection_dropped",
                    aggregate=True,
                    reproduction=_abuse_reproduction(endpoint),
                )
            )
        if leaks:
            findings.append(
                self.finding(
                    title="Error responses leak implementation internals",
                    category="security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    summary=(
                        "Responses to malformed input contained stack traces or engine "
                        f"diagnostics for: {', '.join(leaks)}"
                    ),
                    evidence=json.dumps(
                        [row for row in transcript if row["case"] in leaks], indent=2
                    )[:4000],
                    remediation="Return a stable error code and message; log the detail server "
                    "side only.",
                    location=endpoint,
                    rule="http.abuse.error_leak",
                    aggregate=True,
                    reproduction=_abuse_reproduction(endpoint),
                )
            )
        if alive.error or alive.status == 0:
            findings.append(
                self.finding(
                    title="The service did not survive malformed input",
                    category="correctness",
                    severity=Severity.BLOCKER,
                    confidence=Confidence.CONFIRMED,
                    summary="After the malformed-input sequence the endpoint stopped answering.",
                    evidence=json.dumps(transcript[-2:], indent=2)[:4000],
                    remediation="Contain parse failures so one bad request cannot end the process.",
                    location=endpoint,
                    rule="http.abuse.not_alive",
                    aggregate=True,
                    reproduction=_abuse_reproduction(endpoint),
                )
            )

        status = self.failed if findings else self.verified
        summary = (
            f"{len(cases)} malformed requests produced {len(findings)} problems"
            if findings
            else f"{len(cases)} malformed requests were rejected cleanly and the service stayed up"
        )
        return Outcome(
            checks=[
                status(
                    summary,
                    limitation,
                    evidence_refs=[ref],
                    detail={
                        "cases": [name for name, _ in cases],
                        "unknown_route_status": unknown_route.status,
                    },
                )
            ],
            findings=findings,
        )


def _abuse_reproduction(endpoint: str) -> Reproduction:
    return Reproduction(
        summary="Send a malformed JSON body to the endpoint against a local instance.",
        requires_service=True,
        steps=[
            ReproductionStep(
                description=f"POST {endpoint} with the body `{{not json at all`",
                kind="http_request",
                payload={"method": "POST", "path": endpoint, "raw_body": "{not json at all"},
                expect={},
            )
        ],
    )


class ApiIdempotency(_LiveEvaluator):
    """Repeat a mutating request and record what the artifact actually does."""

    id = "api.idempotency"
    adversary = Adversary.RELIABILITY

    def applicable(self, context: Context) -> tuple[bool, str]:
        applicable, reason = super().applicable(context)
        if not applicable:
            return applicable, reason
        if not (context.config.api and context.config.api.mutating_endpoint):
            return False, "the artifact declares no mutating endpoint to repeat"
        return True, ""

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        assert context.config.api is not None
        endpoint = context.config.api.mutating_endpoint
        body = context.config.api.mutating_body
        first = request(context.service_base_url, "POST", endpoint, body=body)
        second = request(context.service_base_url, "POST", endpoint, body=body)
        transcript = {"first": first.to_dict(), "second": second.to_dict()}
        ref = context.save_evidence_json(self.id, "repeat.json", transcript)
        limitation = (
            "two sequential identical requests; it observes repeat behaviour and does not "
            "establish idempotency under concurrency"
        )
        if second.error or second.status >= 500:
            return Outcome(
                checks=[
                    self.failed(
                        f"repeating the request produced {second.status or second.error}",
                        limitation,
                        evidence_refs=[ref],
                    )
                ],
                findings=[
                    self.finding(
                        title="Repeating a mutating request produces a server error",
                        category="correctness",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        summary=(
                            f"The first {endpoint} call returned {first.status}; an identical "
                            f"second call returned {second.status or second.error}."
                        ),
                        evidence=json.dumps(transcript, indent=2)[:4000],
                        remediation="Make the operation safe to repeat or reject the duplicate "
                        "with a defined client error.",
                        location=endpoint,
                        rule="api.idempotency.repeat_error",
                        reproduction=Reproduction(
                            summary="Send the same mutating request twice.",
                            requires_service=True,
                            steps=[
                                ReproductionStep(
                                    description=f"POST {endpoint} (first)",
                                    kind="http_request",
                                    payload={"method": "POST", "path": endpoint, "body": body},
                                    expect={},
                                ),
                                ReproductionStep(
                                    description=f"POST {endpoint} (second, identical)",
                                    kind="http_request",
                                    payload={"method": "POST", "path": endpoint, "body": body},
                                    expect={"status_gte": 500},
                                ),
                            ],
                        ),
                    )
                ],
            )
        identical = first.body == second.body
        return Outcome(
            checks=[
                self.verified(
                    f"repeating the request returned {second.status}; responses "
                    + ("matched" if identical else "differed, which a create endpoint may intend"),
                    limitation,
                    evidence_refs=[ref],
                    detail={"responses_identical": identical},
                )
            ]
        )


class ServiceRestart(_LiveEvaluator):
    """Stop the artifact and start it again. Recovery behaviour is recorded, not assumed."""

    id = "service.restart"
    adversary = Adversary.RELIABILITY

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        assert context.config.service is not None
        before = request(
            context.service_base_url,
            context.config.service.ready_method,
            context.config.service.ready_path,
            body={} if context.config.service.ready_method == "POST" else None,
        )
        runner = context.service_runner
        if runner is None:
            return Outcome(
                checks=[
                    self.unavailable(
                        "the evaluation holds no handle on the service process, so it cannot "
                        "be restarted safely"
                    )
                ]
            )
        recovered = runner.restart()
        after = request(
            context.service_base_url,
            context.config.service.ready_method,
            context.config.service.ready_path,
            body={} if context.config.service.ready_method == "POST" else None,
        )
        transcript = {
            "before": before.to_dict(),
            "restarted": recovered,
            "after": after.to_dict(),
            "startup_log": runner.startup_log[-4000:],
        }
        ref = context.save_evidence_json(self.id, "restart.json", transcript)
        limitation = (
            "one clean stop and start; it does not simulate a crash, a partial write, or "
            "concurrent traffic during shutdown"
        )
        if recovered and after.status and after.status < 500:
            persisted = before.body == after.body
            return Outcome(
                checks=[
                    self.verified(
                        "the service restarted and answered again; state "
                        + ("survived the restart" if persisted else "did not survive the restart"),
                        limitation,
                        evidence_refs=[ref],
                        detail={"state_persisted": persisted},
                    )
                ]
            )
        return Outcome(
            checks=[
                self.failed(
                    "the service did not come back after a clean restart",
                    limitation,
                    evidence_refs=[ref],
                )
            ],
            findings=[
                self.finding(
                    title="The service does not recover from a clean restart",
                    category="correctness",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    summary="After a terminate and start cycle the ready endpoint did not answer.",
                    evidence=json.dumps(transcript, indent=2)[:4000],
                    remediation="Make startup tolerate the state left by a previous run.",
                    rule="service.restart.no_recovery",
                )
            ],
        )


class PartialRequest(_LiveEvaluator):
    """Abandon a request mid-flight. A server that dies from a truncated header is fragile."""

    id = "reliability.partial_request"
    adversary = Adversary.RELIABILITY

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        parts = urlsplit(context.service_base_url)
        host, port = parts.hostname or "127.0.0.1", parts.port or 80
        sent = []
        for payload in (
            b"POST /api/missions HTTP/1.1\r\nHost: local\r\nContent-Length: 500\r\n\r\n{",
            b"GARBAGE / HTTP/1.1\r\n\r\n",
            b"\x00\x01\x02\x03",
        ):
            try:
                with socket.create_connection((host, port), timeout=5) as connection:
                    connection.sendall(payload)
                    connection.shutdown(socket.SHUT_WR)
                sent.append({"payload": repr(payload)[:120], "delivered": True})
            except OSError as error:
                sent.append(
                    {"payload": repr(payload)[:120], "delivered": False, "error": str(error)}
                )
        assert context.config.service is not None
        alive = request(
            context.service_base_url,
            context.config.service.ready_method,
            context.config.service.ready_path,
            body={} if context.config.service.ready_method == "POST" else None,
        )
        ref = context.save_evidence_json(
            self.id, "partial.json", {"sent": sent, "alive_after": alive.to_dict()}
        )
        limitation = (
            "three truncated or invalid connections; it is not a sustained resource-exhaustion "
            "test and does not measure behaviour under load"
        )
        if alive.status and alive.status < 500:
            return Outcome(
                checks=[
                    self.verified(
                        "the service survived truncated and invalid connections",
                        limitation,
                        evidence_refs=[ref],
                    )
                ]
            )
        return Outcome(
            checks=[
                self.failed(
                    "the service stopped answering after truncated connections",
                    limitation,
                    evidence_refs=[ref],
                )
            ],
            findings=[
                self.finding(
                    title="Truncated connections take the service down",
                    category="correctness",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    summary="After three truncated or invalid connections the service stopped "
                    "answering its ready endpoint.",
                    evidence=json.dumps(sent, indent=2),
                    remediation="Bound and contain connection-level parse failures.",
                    rule="reliability.partial_request.not_alive",
                )
            ],
        )


class StoreCorruption(_LiveEvaluator):
    """Corrupt the artifact's persisted state inside the copy and restart it.

    The corruption is injected, so this check is recorded as SIMULATED. What it
    observes is real: whether the artifact fails clearly or silently misbehaves.
    """

    id = "reliability.corrupt_store"
    adversary = Adversary.RELIABILITY

    def applicable(self, context: Context) -> tuple[bool, str]:
        applicable, reason = super().applicable(context)
        if not applicable:
            return applicable, reason
        if not context.config.service or not context.config.service.start:
            return False, "the artifact declares no startable service"
        return True, ""

    def evaluate(self, context: Context) -> Outcome:
        unavailable = self.offline(context)
        if unavailable:
            return Outcome(checks=[unavailable])
        runner = context.service_runner
        if runner is None:
            return Outcome(checks=[self.unavailable("no service handle is available to restart")])
        stores = [
            name
            for name in context.target.glob("*.json")
            if name.endswith(".json") and "howl" in name.lower()
        ]
        if not stores:
            return Outcome(
                checks=[
                    self.not_applicable(
                        "the running artifact wrote no recognisable persistent store to corrupt"
                    )
                ]
            )
        runner.stop()
        corrupted = stores[0]
        path = context.target.workspace / corrupted
        original = path.read_text()
        path.write_text(original[: len(original) // 2] + "{{ truncated by howlproof")
        recovered = runner.restart()
        assert context.config.service is not None
        after = request(
            context.service_base_url,
            context.config.service.ready_method,
            context.config.service.ready_path,
            body={} if context.config.service.ready_method == "POST" else None,
        )
        transcript = {
            "store": corrupted,
            "restarted": recovered,
            "after": after.to_dict(),
            "startup_log": runner.startup_log[-4000:],
        }
        ref = context.save_evidence_json(self.id, "corrupt-store.json", transcript)
        limitation = (
            "the corruption was injected by the evaluator into the workspace copy, so this is "
            "a simulated fault; the artifact's reaction to it is a real observation"
        )
        clean = (recovered and after.status and after.status < 500) or (
            not recovered and bool(runner.startup_log)
        )
        summary = (
            f"with {corrupted} truncated the artifact "
            + ("started and answered" if recovered and after.status else "refused to start")
            + (" with a diagnostic" if runner.startup_log else " silently")
        )
        if clean:
            return Outcome(
                checks=[
                    self.verified(summary, limitation, evidence_refs=[ref], mode=Mode.SIMULATED)
                ]
            )
        return Outcome(
            checks=[self.failed(summary, limitation, evidence_refs=[ref], mode=Mode.SIMULATED)],
            findings=[
                self.finding(
                    title="Corrupted persistent state fails silently",
                    category="correctness",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"With {corrupted} truncated, the artifact neither started nor emitted a "
                        "diagnostic explaining why."
                    ),
                    evidence=json.dumps(transcript, indent=2)[:4000],
                    remediation="Detect unreadable state at startup and say so on the way out.",
                    rule="reliability.corrupt_store.silent",
                )
            ],
        )


EVALUATORS: list[Evaluator] = [
    HttpAuthorization(),
    HttpAbuse(),
    ApiIdempotency(),
    ServiceRestart(),
    PartialRequest(),
    StoreCorruption(),
]
