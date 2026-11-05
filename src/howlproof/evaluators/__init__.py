"""Built-in evaluators, grouped by the adversary whose question they ask."""

from __future__ import annotations

from howlproof.evaluators import (
    aisurface,
    code,
    concurrency,
    deps,
    httpsurface,
    markup,
    operator,
    publication,
    release,
    research,
    secrets,
    supplychain,
    web,
)
from howlproof.registry import Registry

MODULES = (
    concurrency,
    code,
    secrets,
    supplychain,
    markup,
    httpsurface,
    web,
    aisurface,
    operator,
    publication,
    release,
    research,
    deps,
)


def build_registry() -> Registry:
    registry = Registry()
    register(registry)
    return registry


def register(registry: Registry) -> None:
    for module in MODULES:
        for evaluator in module.EVALUATORS:
            registry.register(evaluator)
