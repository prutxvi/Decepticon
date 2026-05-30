"""Tests for AD attack-path analysis helpers: gpo, delegation, shadow_creds.

All tests are fully offline — no network, no Neo4j, no subprocess.  Graph
fixtures are built with the in-memory KnowledgeGraph helpers (Node.make /
Edge.make / upsert_*).
"""

from __future__ import annotations

from decepticon.tools.ad.delegation import (
    DelegationFinding,
    _is_dc,
    _spn_targets_dc,
    analyze_delegation,
)
from decepticon.tools.ad.gpo import (
    GPOFinding,
    _is_sensitive_ou,
    analyze_gpo_abuse,
)
from decepticon.tools.ad.shadow_creds import (
    ShadowCredsFinding,
    analyze_shadow_credentials,
)
from decepticon_core.types.kg import Edge, EdgeKind, KnowledgeGraph, Node, NodeKind

# ── helpers ──────────────────────────────────────────────────────────────


def _node(label: str, **props: object) -> Node:
    """Construct a generic HOST node — kind is arbitrary for pure-prop tests."""
    return Node.make(NodeKind.HOST, label, **props)


def _user_node(label: str, **props: object) -> Node:
    return Node.make(NodeKind.USER, label, **props)


def _computer_node(label: str, **props: object) -> Node:
    return Node.make(NodeKind.HOST, label, bh_type="Computer", **props)


def _gpo_node(label: str, **props: object) -> Node:
    return Node.make(NodeKind.HOST, label, bh_type="GPO", **props)


def _ou_node(label: str, **props: object) -> Node:
    return Node.make(NodeKind.HOST, label, bh_type="OU", **props)


def _acl_edge(src: Node, dst: Node, right: str) -> Edge:
    return Edge.make(src.id, dst.id, EdgeKind.GRANTS, bh_right=right, key=right)


def _link_edge(src: Node, dst: Node) -> Edge:
    return Edge.make(src.id, dst.id, EdgeKind.CONTAINS, bh_right="GPLink")


def _graph(*nodes: Node, edges: list[Edge] | None = None) -> KnowledgeGraph:
    g = KnowledgeGraph()
    for n in nodes:
        g.upsert_node(n)
    for e in edges or []:
        g.upsert_edge(e)
    return g


# ═══════════════════════════════════════════════════════════════════════════
# GPO helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestIsSensitiveOu:
    def test_matches_domain_controllers_exact(self) -> None:
        assert _is_sensitive_ou("Domain Controllers") is True

    def test_matches_case_insensitive(self) -> None:
        assert _is_sensitive_ou("DOMAIN CONTROLLERS") is True
        assert _is_sensitive_ou("domain controllers") is True

    def test_no_match_for_plain_ou(self) -> None:
        assert _is_sensitive_ou("Finance Users") is False

    def test_empty_string(self) -> None:
        assert _is_sensitive_ou("") is False

    def test_partial_match_in_longer_string(self) -> None:
        assert _is_sensitive_ou("OU=Domain Controllers,DC=corp,DC=local") is True


# ═══════════════════════════════════════════════════════════════════════════
# GPO finding dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestGPOFindingToDict:
    def test_round_trips_all_fields(self) -> None:
        f = GPOFinding(
            gpo_name="Workstation Policy",
            linked_to="Finance OU",
            acl_abuse="GenericWrite",
            severity="high",
            detail="some detail",
        )
        d = f.to_dict()
        assert d["gpo_name"] == "Workstation Policy"
        assert d["linked_to"] == "Finance OU"
        assert d["acl_abuse"] == "GenericWrite"
        assert d["severity"] == "high"
        assert d["detail"] == "some detail"
        assert set(d) == {"gpo_name", "linked_to", "acl_abuse", "severity", "detail"}


# ═══════════════════════════════════════════════════════════════════════════
# analyze_gpo_abuse
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyzeGpoAbuse:
    def test_empty_graph_returns_empty(self) -> None:
        assert analyze_gpo_abuse(KnowledgeGraph()) == []

    def test_no_gpo_nodes_returns_empty(self) -> None:
        u = _user_node("alice@corp.local")
        g = _graph(u)
        assert analyze_gpo_abuse(g) == []

    def test_gpo_no_abusers_returns_empty(self) -> None:
        gpo = _gpo_node("Default Domain Policy")
        g = _graph(gpo)
        assert analyze_gpo_abuse(g) == []

    def test_single_acl_abuse_no_link_produces_finding(self) -> None:
        gpo = _gpo_node("Finance Policy")
        attacker = _user_node("eve@corp.local")
        edge = _acl_edge(attacker, gpo, "GenericWrite")
        g = _graph(gpo, attacker, edges=[edge])

        findings = analyze_gpo_abuse(g)

        assert len(findings) == 1
        f = findings[0]
        assert f.gpo_name == "Finance Policy"
        assert f.acl_abuse == "GenericWrite"
        assert f.severity == "high"  # no DC link → high
        assert "(no linked OUs found)" in f.linked_to

    def test_gpo_linked_to_dc_ou_is_critical(self) -> None:
        gpo = _gpo_node("DC Enforcement Policy")
        attacker = _user_node("eve@corp.local")
        dc_ou = _ou_node("Domain Controllers")
        acl_e = _acl_edge(attacker, gpo, "GenericAll")
        link_e = _link_edge(gpo, dc_ou)
        g = _graph(gpo, attacker, dc_ou, edges=[acl_e, link_e])

        findings = analyze_gpo_abuse(g)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert "Domain Controllers" in f.linked_to
        assert "domain controllers" in f.detail.lower()

    def test_gpo_linked_to_non_dc_ou_is_high(self) -> None:
        gpo = _gpo_node("HR Policy")
        attacker = _user_node("bob@corp.local")
        hr_ou = _ou_node("HR Users")
        acl_e = _acl_edge(attacker, gpo, "WriteDacl")
        link_e = _link_edge(gpo, hr_ou)
        g = _graph(gpo, attacker, hr_ou, edges=[acl_e, link_e])

        findings = analyze_gpo_abuse(g)

        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_multiple_abusers_on_same_gpo(self) -> None:
        gpo = _gpo_node("IT Policy")
        eve = _user_node("eve@corp.local")
        bob = _user_node("bob@corp.local")
        e1 = _acl_edge(eve, gpo, "GenericAll")
        e2 = _acl_edge(bob, gpo, "WriteOwner")
        g = _graph(gpo, eve, bob, edges=[e1, e2])

        findings = analyze_gpo_abuse(g)

        assert len(findings) == 2
        abusers = {f.acl_abuse for f in findings}
        assert "GenericAll" in abusers
        assert "WriteOwner" in abusers

    def test_non_abuse_right_ignored(self) -> None:
        gpo = _gpo_node("Default Policy")
        attacker = _user_node("eve@corp.local")
        # "ReadProperty" is not in _ACL_ABUSE_RIGHTS
        edge = _acl_edge(attacker, gpo, "ReadProperty")
        g = _graph(gpo, attacker, edges=[edge])
        assert analyze_gpo_abuse(g) == []

    def test_acl_edge_pointing_at_non_gpo_node_ignored(self) -> None:
        user_target = _user_node("admin@corp.local")
        attacker = _user_node("eve@corp.local")
        edge = _acl_edge(attacker, user_target, "GenericAll")
        g = _graph(user_target, attacker, edges=[edge])
        assert analyze_gpo_abuse(g) == []

    def test_all_four_abuse_rights_are_detected(self) -> None:
        for right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
            gpo = _gpo_node(f"Policy-{right}")
            attacker = _user_node("eve@corp.local")
            edge = _acl_edge(attacker, gpo, right)
            g = _graph(gpo, attacker, edges=[edge])
            findings = analyze_gpo_abuse(g)
            assert len(findings) == 1, f"{right} should produce a finding"
            assert findings[0].acl_abuse == right

    def test_detail_mentions_attacker_and_gpo_names(self) -> None:
        gpo = _gpo_node("TargetGPO")
        attacker = _user_node("bad_actor@corp.local")
        edge = _acl_edge(attacker, gpo, "GenericWrite")
        g = _graph(gpo, attacker, edges=[edge])
        findings = analyze_gpo_abuse(g)
        assert "bad_actor@corp.local" in findings[0].detail
        assert "TargetGPO" in findings[0].detail

    def test_contains_edge_used_as_link(self) -> None:
        """CONTAINS edge kind (no GPLink bh_right) should also register as a GPO link."""
        gpo = _gpo_node("Linked Policy")
        attacker = _user_node("eve@corp.local")
        dc_ou = _ou_node("Domain Controllers")
        acl_e = _acl_edge(attacker, gpo, "GenericAll")
        # Use CONTAINS kind directly without GPLink bh_right
        contains_e = Edge.make(gpo.id, dc_ou.id, EdgeKind.CONTAINS)
        g = _graph(gpo, attacker, dc_ou, edges=[acl_e, contains_e])

        findings = analyze_gpo_abuse(g)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_missing_src_node_skips_abuser(self) -> None:
        """Edge referencing a non-existent src node should not crash."""
        gpo = _gpo_node("Orphan Policy")
        # Create edge with a dangling src id
        edge = Edge.make("non-existent-src", gpo.id, EdgeKind.GRANTS, bh_right="GenericAll")
        g = KnowledgeGraph()
        g.upsert_node(gpo)
        g.upsert_edge(edge)
        findings = analyze_gpo_abuse(g)
        assert findings == []

    def test_missing_dst_node_skips_link(self) -> None:
        """GPLink edge with dangling dst should not crash."""
        gpo = _gpo_node("Dangling Link Policy")
        attacker = _user_node("eve@corp.local")
        acl_e = _acl_edge(attacker, gpo, "GenericAll")
        dangling_link = Edge.make(gpo.id, "non-existent-ou", EdgeKind.CONTAINS, bh_right="GPLink")
        g = _graph(gpo, attacker, edges=[acl_e, dangling_link])
        # Should not crash and should produce a finding
        findings = analyze_gpo_abuse(g)
        assert len(findings) == 1
        # Dangling link was silently ignored — no OU label in linked_to
        assert "(no linked OUs found)" in findings[0].linked_to


# ═══════════════════════════════════════════════════════════════════════════
# Delegation helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestIsDc:
    def test_computer_with_is_dc_flag(self) -> None:
        assert _is_dc({"bh_type": "Computer", "is_dc": True, "label": "DC01"}) is True

    def test_computer_with_domain_controller_in_label(self) -> None:
        props = {"bh_type": "Computer", "is_dc": False, "label": "DOMAIN CONTROLLER"}
        assert _is_dc(props) is True

    def test_computer_plain(self) -> None:
        assert _is_dc({"bh_type": "Computer", "label": "WS01"}) is False

    def test_non_computer_type(self) -> None:
        assert _is_dc({"bh_type": "User", "is_dc": True, "label": "DC01"}) is False

    def test_empty_props(self) -> None:
        assert _is_dc({}) is False


class TestSpnTargetsDc:
    def test_ldap_spn(self) -> None:
        assert _spn_targets_dc("ldap/dc01.corp.local") is True

    def test_cifs_spn(self) -> None:
        assert _spn_targets_dc("cifs/fileserver.corp.local") is True

    def test_http_spn(self) -> None:
        assert _spn_targets_dc("http/webapp.corp.local") is True

    def test_mssql_spn(self) -> None:
        assert _spn_targets_dc("mssql/sqlsrv.corp.local") is True

    def test_krbtgt_spn(self) -> None:
        assert _spn_targets_dc("krbtgt/corp.local") is True

    def test_host_spn(self) -> None:
        assert _spn_targets_dc("host/dc01.corp.local") is True

    def test_unknown_spn(self) -> None:
        assert _spn_targets_dc("nfs/storage.corp.local") is False

    def test_case_insensitive(self) -> None:
        assert _spn_targets_dc("LDAP/DC01.CORP.LOCAL") is True

    def test_empty_string(self) -> None:
        assert _spn_targets_dc("") is False


# ═══════════════════════════════════════════════════════════════════════════
# DelegationFinding dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestDelegationFindingToDict:
    def test_to_dict_contains_all_fields(self) -> None:
        f = DelegationFinding(
            target="FILESERVER$",
            delegation_type="unconstrained",
            severity="high",
            detail="detail text",
            attack_path=["FILESERVER$"],
        )
        d = f.to_dict()
        assert d["target"] == "FILESERVER$"
        assert d["delegation_type"] == "unconstrained"
        assert d["severity"] == "high"
        assert d["attack_path"] == ["FILESERVER$"]
        assert set(d) == {"target", "delegation_type", "severity", "detail", "attack_path"}


# ═══════════════════════════════════════════════════════════════════════════
# analyze_delegation
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyzeDelegation:
    def test_empty_graph(self) -> None:
        assert analyze_delegation(KnowledgeGraph()) == []

    def test_no_computer_nodes(self) -> None:
        u = _user_node("alice@corp.local")
        g = _graph(u)
        assert analyze_delegation(g) == []

    # --- unconstrained delegation ---

    def test_unconstrained_via_trustedfordelegation(self) -> None:
        ws = _computer_node("WORKSTATION01$", trustedfordelegation=True)
        g = _graph(ws)
        findings = analyze_delegation(g)
        assert len(findings) == 1
        f = findings[0]
        assert f.delegation_type == "unconstrained"
        assert f.severity == "high"
        assert "WORKSTATION01$" in f.target

    def test_unconstrained_via_unconstraineddelegation(self) -> None:
        ws = _computer_node("WEB01$", unconstraineddelegation=True)
        g = _graph(ws)
        findings = analyze_delegation(g)
        assert len(findings) == 1
        assert findings[0].delegation_type == "unconstrained"

    def test_dc_with_unconstrained_is_skipped(self) -> None:
        dc = _computer_node("DC01$", trustedfordelegation=True, is_dc=True)
        g = _graph(dc)
        assert analyze_delegation(g) == []

    def test_computer_without_delegation_flags_skipped(self) -> None:
        ws = _computer_node("PLAIN_WS$")
        g = _graph(ws)
        assert analyze_delegation(g) == []

    def test_unconstrained_attack_path_is_single_node(self) -> None:
        ws = _computer_node("SRV01$", trustedfordelegation=True)
        g = _graph(ws)
        f = analyze_delegation(g)[0]
        assert f.attack_path == ["SRV01$"]

    # --- constrained delegation ---

    def test_constrained_delegation_sensitive_spn(self) -> None:
        src = _computer_node("SVC01$")
        dst = _computer_node("DC01$")
        edge = Edge.make(
            src.id,
            dst.id,
            EdgeKind.GRANTS,
            bh_right="AllowedToDelegate",
            spn="ldap/dc01.corp.local",
        )
        g = _graph(src, dst, edges=[edge])
        findings = analyze_delegation(g)
        assert len(findings) == 1
        f = findings[0]
        assert f.delegation_type == "constrained"
        assert f.severity == "high"
        assert "SVC01$" in f.detail
        assert "DC01$" in f.detail

    def test_constrained_delegation_non_sensitive_spn(self) -> None:
        src = _computer_node("SVC02$")
        dst = _computer_node("PRINT01$")
        edge = Edge.make(
            src.id,
            dst.id,
            EdgeKind.GRANTS,
            bh_right="AllowedToDelegate",
            spn="nfs/print01.corp.local",
        )
        g = _graph(src, dst, edges=[edge])
        findings = analyze_delegation(g)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_constrained_falls_back_to_dst_label_when_no_spn(self) -> None:
        src = _computer_node("SVC03$")
        dst = _computer_node("BACKUP$")
        edge = Edge.make(src.id, dst.id, EdgeKind.GRANTS, bh_right="AllowedToDelegate")
        g = _graph(src, dst, edges=[edge])
        findings = analyze_delegation(g)
        assert len(findings) == 1
        # dst label used as fallback SPN — BACKUP$ contains no sensitive prefix
        assert findings[0].severity == "medium"

    def test_constrained_attack_path_has_two_nodes(self) -> None:
        src = _computer_node("SVC01$")
        dst = _computer_node("DC01$")
        edge = Edge.make(src.id, dst.id, EdgeKind.GRANTS, bh_right="AllowedToDelegate")
        g = _graph(src, dst, edges=[edge])
        f = analyze_delegation(g)[0]
        assert f.attack_path == ["SVC01$", "DC01$"]

    # --- RBCD ---

    def test_rbcd_finding(self) -> None:
        attacker = _computer_node("ATTACKER$")
        target = _computer_node("TARGET$")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AllowedToAct")
        g = _graph(attacker, target, edges=[edge])
        findings = analyze_delegation(g)
        assert len(findings) == 1
        f = findings[0]
        assert f.delegation_type == "rbcd"
        assert f.severity == "medium"
        assert "ATTACKER$" in f.detail
        assert "TARGET$" in f.detail
        assert f.attack_path == ["ATTACKER$", "TARGET$"]

    def test_unrelated_edge_right_ignored(self) -> None:
        src = _computer_node("A$")
        dst = _computer_node("B$")
        edge = Edge.make(src.id, dst.id, EdgeKind.GRANTS, bh_right="GenericAll")
        g = _graph(src, dst, edges=[edge])
        # GenericAll is not AllowedToDelegate / AllowedToAct
        assert analyze_delegation(g) == []

    def test_missing_src_node_skips_edge(self) -> None:
        dst = _computer_node("TARGET$")
        edge = Edge.make("missing-src", dst.id, EdgeKind.GRANTS, bh_right="AllowedToDelegate")
        g = KnowledgeGraph()
        g.upsert_node(dst)
        g.upsert_edge(edge)
        assert analyze_delegation(g) == []

    def test_missing_dst_node_skips_edge(self) -> None:
        src = _computer_node("SRC$")
        edge = Edge.make(src.id, "missing-dst", EdgeKind.GRANTS, bh_right="AllowedToAct")
        g = KnowledgeGraph()
        g.upsert_node(src)
        g.upsert_edge(edge)
        assert analyze_delegation(g) == []

    def test_unconstrained_and_rbcd_both_returned(self) -> None:
        ws = _computer_node("WS01$", trustedfordelegation=True)
        attacker = _computer_node("ATT$")
        target = _computer_node("TARGET$")
        rbcd_edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AllowedToAct")
        g = _graph(ws, attacker, target, edges=[rbcd_edge])
        findings = analyze_delegation(g)
        types = {f.delegation_type for f in findings}
        assert "unconstrained" in types
        assert "rbcd" in types


# ═══════════════════════════════════════════════════════════════════════════
# ShadowCredsFinding dataclass
# ═══════════════════════════════════════════════════════════════════════════


class TestShadowCredsToDict:
    def test_to_dict_contains_all_fields(self) -> None:
        f = ShadowCredsFinding(
            attacker="eve@corp.local",
            target="admin@corp.local",
            severity="high",
            detail="some detail",
        )
        d = f.to_dict()
        assert d["attacker"] == "eve@corp.local"
        assert d["target"] == "admin@corp.local"
        assert d["severity"] == "high"
        assert set(d) == {"attacker", "target", "severity", "detail"}


# ═══════════════════════════════════════════════════════════════════════════
# analyze_shadow_credentials
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyzeShadowCredentials:
    def test_empty_graph(self) -> None:
        assert analyze_shadow_credentials(KnowledgeGraph()) == []

    def test_no_relevant_edges(self) -> None:
        u = _user_node("alice@corp.local", bh_type="User")
        g = _graph(u)
        assert analyze_shadow_credentials(g) == []

    def test_add_key_credential_link_on_user(self) -> None:
        attacker = _user_node("eve@corp.local")
        target = _user_node("admin@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        g = _graph(attacker, target, edges=[edge])
        findings = analyze_shadow_credentials(g)
        assert len(findings) == 1
        f = findings[0]
        assert f.attacker == "eve@corp.local"
        assert f.target == "admin@corp.local"
        assert "msDS-KeyCredentialLink" in f.detail
        assert "Shadow Credentials" in f.detail

    def test_add_key_credential_link_on_computer(self) -> None:
        attacker = _user_node("eve@corp.local")
        target = _computer_node("WS01$")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        g = _graph(attacker, target, edges=[edge])
        findings = analyze_shadow_credentials(g)
        assert len(findings) == 1
        assert findings[0].target == "WS01$"

    def test_generic_all_on_user_triggers_shadow_creds(self) -> None:
        attacker = _user_node("bad@corp.local")
        target = _user_node("victim@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="GenericAll")
        g = _graph(attacker, target, edges=[edge])
        findings = analyze_shadow_credentials(g)
        assert len(findings) == 1
        f = findings[0]
        assert "GenericAll" in f.detail
        assert "msDS-KeyCredentialLink" in f.detail

    def test_generic_write_on_user(self) -> None:
        attacker = _user_node("bad@corp.local")
        target = _user_node("victim@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="GenericWrite")
        g = _graph(attacker, target, edges=[edge])
        findings = analyze_shadow_credentials(g)
        assert len(findings) == 1
        assert findings[0].target == "victim@corp.local"

    def test_low_priv_attacker_severity_is_high(self) -> None:
        attacker = _user_node("low@corp.local", admincount=False)
        target = _user_node("admin@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        g = _graph(attacker, target, edges=[edge])
        assert analyze_shadow_credentials(g)[0].severity == "high"

    def test_high_priv_attacker_severity_is_medium(self) -> None:
        attacker = _user_node("admin2@corp.local", admincount=True)
        target = _user_node("admin@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        g = _graph(attacker, target, edges=[edge])
        assert analyze_shadow_credentials(g)[0].severity == "medium"

    def test_target_must_be_user_or_computer(self) -> None:
        attacker = _user_node("eve@corp.local")
        # bh_type="GPO" is not in _TARGET_BH_TYPES — override explicitly
        non_target_with_type = Node.make(NodeKind.HOST, "Some Policy", bh_type="GPO")
        edge = Edge.make(
            attacker.id, non_target_with_type.id, EdgeKind.GRANTS, bh_right="GenericAll"
        )
        g = _graph(attacker, non_target_with_type, edges=[edge])
        assert analyze_shadow_credentials(g) == []

    def test_unrelated_right_ignored(self) -> None:
        attacker = _user_node("eve@corp.local")
        target = _user_node("admin@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="ReadProperty")
        g = _graph(attacker, target, edges=[edge])
        assert analyze_shadow_credentials(g) == []

    def test_missing_src_node_skips_finding(self) -> None:
        target = _user_node("admin@corp.local", bh_type="User")
        edge = Edge.make("missing-src", target.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        g = KnowledgeGraph()
        g.upsert_node(target)
        g.upsert_edge(edge)
        assert analyze_shadow_credentials(g) == []

    def test_missing_dst_node_skips_finding(self) -> None:
        attacker = _user_node("eve@corp.local")
        edge = Edge.make(
            attacker.id, "missing-dst", EdgeKind.GRANTS, bh_right="AddKeyCredentialLink"
        )
        g = KnowledgeGraph()
        g.upsert_node(attacker)
        g.upsert_edge(edge)
        assert analyze_shadow_credentials(g) == []

    def test_multiple_targets_multiple_findings(self) -> None:
        attacker = _user_node("eve@corp.local")
        t1 = _user_node("user1@corp.local", bh_type="User")
        t2 = _user_node("user2@corp.local", bh_type="User")
        e1 = Edge.make(attacker.id, t1.id, EdgeKind.GRANTS, bh_right="AddKeyCredentialLink")
        e2 = Edge.make(attacker.id, t2.id, EdgeKind.GRANTS, bh_right="GenericAll")
        g = _graph(attacker, t1, t2, edges=[e1, e2])
        findings = analyze_shadow_credentials(g)
        assert len(findings) == 2
        targets = {f.target for f in findings}
        assert "user1@corp.local" in targets
        assert "user2@corp.local" in targets

    def test_detail_mentions_pywhisker_for_generic_rights(self) -> None:
        attacker = _user_node("bad@corp.local")
        target = _user_node("victim@corp.local", bh_type="User")
        edge = Edge.make(attacker.id, target.id, EdgeKind.GRANTS, bh_right="GenericWrite")
        g = _graph(attacker, target, edges=[edge])
        detail = analyze_shadow_credentials(g)[0].detail
        assert "Whisker" in detail or "pyWhisker" in detail
