"""Built-in evaluators, grouped by the adversary whose question they ask."""

from __future__ import annotations

from howlproof.evaluators import (
    aisurface,
    code,
    deps,
    httpsurface,
    markup,
    operator,
    release,
    secrets,
    supplychain,
    web,
)
from howlproof.registry import Registry

MODULES = (code, secrets, supplychain, markup, httpsurface, web, aisurface, operator, release, deps)


def build_registry() -> Registry:
    registry = Registry()
    register(registry)
    return registry


def register(registry: Registry) -> None:
    for module in MODULES:
        for evaluator in module.EVALUATORS:
            registry.register(evaluator)
