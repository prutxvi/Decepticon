"""Skillogy clients (REST + gRPC)."""

from decepticon.skillogy.client.rest import RestSkillogyClient, SkillogyClientError

__all__ = ["RestSkillogyClient", "SkillogyClientError"]
