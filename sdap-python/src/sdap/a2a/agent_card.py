"""A2A Agent Card SDAP extension builder."""

from __future__ import annotations


def build_sdap_extension(
    did: str,
    handshake_endpoint: str,
    supported_layers: list[int],
    min_security_level: str = "basic",
) -> dict:
    """Build the ``sdap`` extension object for an A2A Agent Card.

    This extension advertises the agent's SDAP capabilities and endpoints
    within the standard A2A Agent Card format.

    Args:
        did: The agent's DID (``did:sdap:...``).
        handshake_endpoint: HTTPS URL for the SDAP handshake endpoint.
        supported_layers: List of supported SDAP protocol layer numbers (e.g. [1, 2, 3]).
        min_security_level: Minimum security level required (``basic``, ``standard``,
            ``high``, or ``critical``).

    Returns:
        A dict representing the ``sdap`` extension object.
    """
    valid_security_levels = {"basic", "standard", "high", "critical"}
    if min_security_level not in valid_security_levels:
        raise ValueError(
            f"min_security_level must be one of {valid_security_levels}, "
            f"got {min_security_level!r}"
        )

    return {
        "sdap": {
            "version": "1.0",
            "did": did,
            "handshakeEndpoint": handshake_endpoint,
            "supportedLayers": supported_layers,
            "minSecurityLevel": min_security_level,
        }
    }
