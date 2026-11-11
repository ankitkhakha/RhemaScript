#!/usr/bin/env python3
"""Dependency-free local CI runner for RhemaScript NEW SYSTEM contract coverage."""
import compileall, pathlib, subprocess, sys, tomllib
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
def main():
    print("=== RhemaScript NEW SYSTEM FULL-SYSTEM CONTRACT CI ===",flush=True)
    print("[1/4] Compile all source and test modules",flush=True)
    if not compileall.compile_dir(str(ROOT/"rhemascript"),quiet=1): return 1
    if not compileall.compile_dir(str(ROOT/"tests"),quiet=1): return 1
    print("[2/4] Validate package metadata",flush=True)
    with (ROOT/"pyproject.toml").open("rb") as f: metadata=tomllib.load(f)
    assert metadata["project"]["name"]=="rhemascript-new-system"
    assert metadata["project"]["requires-python"]==">=3.11"
    print("[3/4] Validate capability and interface contract registries",flush=True)
    from rhemascript.registry.system_registry import CAPABILITIES, INTERFACES
    assert len(CAPABILITIES)==15 and len(INTERFACES)==18
    print(f"Registry coverage: {len(CAPABILITIES)}/15 capabilities; {len(INTERFACES)}/18 interfaces",flush=True)
    print("[4/4] Run all unit, negative, governance and registry tests",flush=True)
    result=subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-v"],cwd=ROOT)
    if result.returncode: return result.returncode
    print("CI RESULT: PASS",flush=True); return 0
if __name__=="__main__": raise SystemExit(main())
