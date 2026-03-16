"""SDAP A2A integration module — Agent Card extension, message wrapping, and high-level client."""

from sdap.a2a.agent_card import build_sdap_extension
from sdap.a2a.client import SDAPClient
from sdap.a2a.middleware import unwrap_a2a_message, wrap_a2a_message

__all__ = [
    "SDAPClient",
    "build_sdap_extension",
    "unwrap_a2a_message",
    "wrap_a2a_message",
]
