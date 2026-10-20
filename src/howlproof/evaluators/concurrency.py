"""Bounded parallel creates against an explicitly declared local endpoint."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import uuid4

from howlproof.model import Adversary, Confidence, Severity
from howlproof.registry import Context, Evaluator, Outcome
from howlproof.service import HttpResponse, request


class ApiConcurrency(Evaluator):
    """Challenge response identifier uniqueness under concurrent create requests."""

    id = "api.concurrency"
    adversary = Adversary.FUNCTIONAL

    def applicable(self, context: Context) -> tuple[bool, str]:
        if context.config.api and context.config.api.concurrent_create:
            return True, ""
        return False, "no concurrent create probe is declared"

    def evaluate(self, context: Context) -> Outcome:
        assert context.config.api and context.config.api.concurrent_create
        probe = context.config.api.concurrent_create
        if not context.service_running:
            return Outcome(checks=[self.unavailable("the declared service is not running")])
        prefix = uuid4().hex

        def create(index: int) -> HttpResponse:
            body = {**probe.body, probe.request_id_field: f"{prefix}-{index}"}
            return request(context.service_base_url, "POST", probe.path, body=body, timeout=10)

        with ThreadPoolExecutor(max_workers=min(probe.workers, probe.requests)) as pool:
            responses = list(pool.map(create, range(probe.requests)))
        identifiers: list[str] = []
        invalid: list[int] = []
        for index, response in enumerate(responses):
            payload = response.json()
            identifier: Any = payload.get(probe.id_field) if isinstance(payload, dict) else None
            if (
                not 200 <= response.status < 300
                or response.error
                or isinstance(identifier, bool)
                or not isinstance(identifier, (str, int))
                or identifier == ""
            ):
                invalid.append(index)
            else:
                identifiers.append(str(identifier))
        collisions = {key: count for key, count in Counter(identifiers).items() if count > 1}
        ref = context.save_evidence_json(
            self.id,
            "parallel-creates.json",
            {
                "requests": probe.requests,
                "workers": probe.workers,
                "responses": [response.to_dict() for response in responses],
                "invalid_responses": invalid,
                "duplicate_ids": collisions,
            },
        )
        limitation = (
            "one bounded burst of distinct create requests checks response ID uniqueness; "
            "it does not establish durable storage, absence of lost updates, or race freedom"
        )
        if collisions:
            return Outcome(
                checks=[
                    self.failed(
                        "distinct concurrent creates returned duplicate identifiers",
                        limitation,
                        evidence_refs=[ref],
                        detail={"duplicate_ids": collisions},
                    )
                ],
                findings=[
                    self.finding(
                        title="Concurrent creates returned colliding identifiers",
                        category="correctness",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        summary=(
                            f"Distinct requests returned {len(collisions)} duplicate identifiers."
                        ),
                        evidence=(f"{ref}: {len(collisions)} identifiers appeared more than once"),
                        remediation=(
                            "Allocate identifiers atomically and enforce uniqueness at storage."
                        ),
                        rule="api.concurrency.colliding_ids",
                        aggregate=True,
                    )
                ],
            )
        if invalid:
            check = self.errored(
                f"{len(invalid)} create responses failed or lacked the declared identifier; "
                "uniqueness could not be established"
            )
            check.evidence_refs = [ref]
            return Outcome(checks=[check])
        return Outcome(
            checks=[
                self.verified(
                    f"{len(identifiers)} concurrent creates returned distinct identifiers",
                    limitation,
                    evidence_refs=[ref],
                )
            ]
        )


EVALUATORS: list[Evaluator] = [ApiConcurrency()]
