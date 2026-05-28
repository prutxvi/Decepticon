"""Hand-rolled Python message types that mirror skillogy.proto.

These dataclasses exist so the package is functional today without a
protoc-generated module. A CI step (planned in a follow-up) will codegen
``skillogy_pb2.py`` from skillogy.proto and assert that the field
positions + names match these dataclasses, so the two stay in sync.

The wire format for REST is JSON serialization of these dataclasses
(field names verbatim). The gRPC server uses the codegen module when
available and falls back to dict <-> dataclass conversion otherwise.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class SkillMeta:
    name: str = ""
    description: str = ""
    subdomain: str = ""
    tags: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    path: str = ""
    content_sha256: str = ""
    size_bytes: int = 0
    safety_critical: bool = False
    gated_by_conops: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SkillEnvelope:
    meta: SkillMeta = field(default_factory=SkillMeta)
    body: str = ""
    references: dict[str, bytes] = field(default_factory=dict)
    scripts: dict[str, bytes] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta.to_dict(),
            "body": self.body,
            "references": {k: v.decode("utf-8", errors="replace") for k, v in self.references.items()},
            "scripts": {k: v.decode("utf-8", errors="replace") for k, v in self.scripts.items()},
        }


@dataclass
class SkillListRequest:
    subdomain_filter: list[str] = field(default_factory=list)
    tag_filter: list[str] = field(default_factory=list)
    mitre_filter: list[str] = field(default_factory=list)
    include_safety_critical: bool = True
    include_gated: bool = True
    page_size: int = 100
    page_token: str = ""


@dataclass
class SkillListResponse:
    skills: list[SkillMeta] = field(default_factory=list)
    next_page_token: str = ""
    total_count: int = 0

    def to_dict(self) -> dict:
        return {
            "skills": [s.to_dict() for s in self.skills],
            "next_page_token": self.next_page_token,
            "total_count": self.total_count,
        }


@dataclass
class SkillLoadRequest:
    path: str = ""
    include_references: bool = True
    include_scripts: bool = True


@dataclass
class SkillIngestRequest:
    path: str = ""
    body: str = ""
    references: dict[str, bytes] = field(default_factory=dict)
    scripts: dict[str, bytes] = field(default_factory=dict)


@dataclass
class SkillIngestResponse:
    path: str = ""
    content_sha256: str = ""
    created: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


__all__ = [
    "SkillEnvelope",
    "SkillIngestRequest",
    "SkillIngestResponse",
    "SkillListRequest",
    "SkillListResponse",
    "SkillLoadRequest",
    "SkillMeta",
]
