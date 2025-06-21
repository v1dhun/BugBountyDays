#!/usr/bin/env python3
import os
import sys
import stat
import shutil
import zipfile
import plistlib
import subprocess
import platform
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# ========== CONFIG ==========
# brew install ldid
# Ref: 
# https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0111/
# https://github.com/ProcursusTeam/ldid
LDID_BIN = "ldid" 
ENTITLEMENTS_FLAG = "-S"
MAX_JOBS = 4
WORK_DIR = Path("workdir")
# ============================

# ========== LOGGING ==========
def info(msg): print(f"\033[1;32m[INFO]\033[0m {msg}")
def warn(msg): print(f"\033[1;33m[WARN]\033[0m {msg}")
def fail(msg): print(f"\033[1;31m[FAIL]\033[0m {msg}"); sys.exit(1)
# =============================

def validate_tools():
    required = [LDID_BIN, "unzip", "tar"]
    if platform.system() == "Darwin":
        required.append("ditto")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        for tool in missing:
            warn(f"Required tool not found: {tool}")
        fail("Install missing tools and try again.")
    info("All required tools found.")

def detect_format(path: Path) -> str:
    with path.open("rb") as f:
        magic = f.read(4)
    if magic.startswith(b"PK\x03\x04"):
        return "zip"
    elif magic.startswith(b"\x1f\x8b"):
        return "gzip"
    fail("Unsupported or unknown IPA format")

def extract_ipa(path: Path, fmt: str, dest: Path):
    if fmt == "zip":
        info("Extracting .zip IPA...")
        subprocess.run(["unzip", "-q", str(path), "-d", str(dest)], check=True)
    elif fmt == "gzip":
        info("Extracting .tar.gz IPA...")
        subprocess.run(["tar", "-xzf", str(path), "-C", str(dest)], check=True)

def find_app_bundle(payload: Path) -> Path:
    for app in payload.glob("*.app"):
        if app.is_dir():
            return app
    fail("No .app bundle found in Payload/")

def get_main_binary(app: Path) -> Path:
    plist = app / "Info.plist"
    if not plist.exists():
        warn("Missing Info.plist; using app name as fallback")
        return app / app.name
    with plist.open("rb") as f:
        meta = plistlib.load(f)
    name = meta.get("CFBundleExecutable", app.name)
    return app / name

def cleanup_signatures(app: Path):
    info("Cleaning old signatures...")
    shutil.rmtree(app / "_CodeSignature", ignore_errors=True)
    for name in ["CodeResources", "PkgInfo", "embedded.mobileprovision"]:
        (app / name).unlink(missing_ok=True)
    for item in app.glob("SC_Info*"):
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

def sign(path: Path):
    if not path.exists():
        warn(f"Missing binary: {path}")
        return
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    info(f"→ Signing: {path}")
    try:
        subprocess.run([LDID_BIN, ENTITLEMENTS_FLAG, str(path)], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        warn(f"Failed to sign: {path}")

def sign_embedded(app: Path):
    fw_dir = app / "Frameworks"
    if not fw_dir.exists():
        warn("No Frameworks/ directory found.")
        return

    binaries = []
    for fw in fw_dir.glob("*.framework"):
        bin_path = fw / fw.stem
        if bin_path.exists():
            binaries.append(bin_path)
        else:
            warn(f"Missing framework binary in {fw}")

    binaries += list(fw_dir.glob("*.dylib"))

    info(f"Signing {len(binaries)} embedded binaries in parallel...")
    with ThreadPoolExecutor(MAX_JOBS) as pool:
        pool.map(sign, binaries)

def repack_with_ditto(payload_dir: Path, output: Path):
    info(f"Repacking using 'ditto' → {output}")
    try:
        subprocess.run([
            "ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
            str(payload_dir), str(output)
        ], check=True)
    except subprocess.CalledProcessError:
        fail("Failed to repack with ditto")

def repack_with_zip(payload_dir: Path, output: Path):
    info(f"Repacking using Python zip → {output}")
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED) as ipa:
        for root, _, files in os.walk(payload_dir):
            for file in files:
                full_path = Path(root) / file
                arcname = full_path.relative_to(WORK_DIR)
                ipa.write(full_path, arcname)

def repack(payload_dir: Path, output: Path):
    if platform.system() == "Darwin" and shutil.which("ditto"):
        repack_with_ditto(payload_dir, output)
    else:
        repack_with_zip(payload_dir, output)

def main():
    if len(sys.argv) != 2:
        fail("Usage: python3 resign.py <App.ipa>")

    ipa = Path(sys.argv[1]).resolve()
    if not ipa.is_file():
        fail("Invalid IPA path")

    app_name = ipa.stem
    out_ipa = ipa.with_name(f"{app_name}_patched.ipa")

    shutil.rmtree(WORK_DIR, ignore_errors=True)
    if out_ipa.exists(): out_ipa.unlink()
    WORK_DIR.mkdir()

    validate_tools()
    fmt = detect_format(ipa)
    extract_ipa(ipa, fmt, WORK_DIR)

    payload = WORK_DIR / "Payload"
    if not payload.exists():
        fail("Payload/ folder not found")

    app = find_app_bundle(payload)
    info(f"App bundle: {app}")

    cleanup_signatures(app)

    main_bin = get_main_binary(app)
    if not main_bin.exists():
        fail(f"Main binary not found: {main_bin}")
    sign(main_bin)

    sign_embedded(app)
    repack(payload, out_ipa)
    info(f"IPA re-signed and repackaged → {out_ipa}")

if __name__ == "__main__":
    main()
