"""
channels — Advanced delivery channels for Project Anubis.

Provides a smart orchestrator that asks the user how to deliver,
then coordinates phishing, messaging, Cloudflare, and artifact
identification subsystems.
"""

from .orchestrator import DeliveryOrchestrator
from .phishing_engine import PhishingEngine, PhishingTemplate
from .messaging import MessagingChannels, ChannelType
from .cloudflare import CloudflareUtils
from .artifact_id import ArtifactIdentifier, ArtifactClass, RiskLevel

__all__ = [
    "DeliveryOrchestrator",
    "PhishingEngine",
    "PhishingTemplate",
    "MessagingChannels",
    "ChannelType",
    "CloudflareUtils",
    "ArtifactIdentifier",
    "ArtifactClass",
    "RiskLevel",
]


def create_orchestrator(
    telemetry=None,
    delivery_pipeline=None,
    compat=None,
    interactive: bool = True,
) -> DeliveryOrchestrator:
    """Factory: build a fully wired DeliveryOrchestrator."""
    engine = DeliveryOrchestrator(
        telemetry=telemetry,
        delivery_pipeline=delivery_pipeline,
        compat=compat,
        interactive=interactive,
    )
    return engine
