from __future__ import annotations

import json

from decepticon.tools.reversing.ghidra import _GHIDRA_FUNC_KEYS, GhidraAnalysis, GhidraFunction
from decepticon.tools.reversing.scripts import ghidra_recon_script, r2_recon_script
from decepticon.tools.reversing.tools import bin_r2_script


class TestGhidraFunctionExtraKeys:
    def test_extra_keys_do_not_raise(self) -> None:
        extra = {
            "name": "sub_401000",
            "address": "0x401000",
            "size": 42,
            "calling_convention": "__cdecl",
            "signature": "void sub_401000(void)",
            "thunk": True,
            "namespace": "Global",
            "unknown_future_field": "ignored",
        }
        fn = GhidraFunction(**{k: v for k, v in extra.items() if k in _GHIDRA_FUNC_KEYS})
        assert fn.name == "sub_401000"
        assert fn.address == "0x401000"
        assert fn.size == 42
        assert fn.calling_convention == "__cdecl"
        assert fn.signature == "void sub_401000(void)"

    def test_ghidra_analysis_with_extra_function_fields(self) -> None:
        funcs_data = [
            {
                "name": "main",
                "address": "0x401234",
                "size": 100,
                "calling_convention": "__cdecl",
                "signature": "int main(int, char **)",
                "thunk": False,
                "namespace": "Global",
            }
        ]
        data = {
            "program_name": "test.exe",
            "language": "x86:LE:64:default",
            "image_base": "0x400000",
            "function_count": 1,
            "functions": funcs_data,
        }
        analysis = GhidraAnalysis(
            program_name=data["program_name"],
            language=data["language"],
            image_base=data["image_base"],
            function_count=data["function_count"],
            functions=[
                GhidraFunction(**{k: v for k, v in f.items() if k in _GHIDRA_FUNC_KEYS})
                for f in data["functions"][:500]
            ],
        )
        assert len(analysis.functions) == 1
        assert analysis.functions[0].name == "main"


class TestScriptsBracePath:
    def test_ghidra_recon_script_brace_in_binary(self) -> None:
        binary = "/tmp/{evil}/target{x}"
        src = ghidra_recon_script(binary)
        assert binary in src
        assert src.count("{binary}") == 0

    def test_ghidra_recon_script_brace_in_script_name(self) -> None:
        binary = "/bin/ls"
        script_name = "my{script}.py"
        src = ghidra_recon_script(binary, script_name)
        assert script_name in src
        assert src.count("{script_name}") == 0

    def test_r2_recon_script_brace_in_binary(self) -> None:
        binary = "/tmp/{malicious}"
        src = r2_recon_script(binary)
        assert binary in src
        assert src.count("{binary}") == 0

    def test_scripts_normal_path_preserved(self) -> None:
        binary = "/workspace/target"
        gsrc = ghidra_recon_script(binary)
        assert binary in gsrc
        rsrc = r2_recon_script(binary)
        assert binary in rsrc


class TestBinR2ScriptNoDeadReturn:
    def test_returns_json_with_source_key(self) -> None:
        result = bin_r2_script.invoke({"binary": "/bin/ls"})
        parsed = json.loads(result)
        assert "source" in parsed
        assert isinstance(parsed["source"], str)
        assert len(parsed["source"]) > 50

    def test_brace_in_binary_does_not_raise(self) -> None:
        result = bin_r2_script.invoke({"binary": "/tmp/{bad}"})
        parsed = json.loads(result)
        assert "source" in parsed


class TestGhidraReconEntryPoint:
    def test_recon_script_does_not_iterate_single_entry_point(self) -> None:
        src = ghidra_recon_script("/workspace/target")
        assert "for a in f.getEntryPoint()" not in src
        assert "f.getEntryPoint()" in src
