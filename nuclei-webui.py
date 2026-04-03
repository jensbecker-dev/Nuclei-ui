from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"


def _ensure_python_dependencies() -> None:
    required_modules = [
        "flask",
        "flask_sqlalchemy",
        "flask_login",
        "dotenv",
    ]

    missing = []
    for module_name in required_modules:
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(module_name)

    if not missing:
        return

    if not REQUIREMENTS_FILE.exists():
        raise RuntimeError(
            f"Missing Python modules ({', '.join(missing)}) and requirements.txt was not found at {REQUIREMENTS_FILE}."
        )

    print(f"[bootstrap] Missing modules detected: {', '.join(missing)}")
    print("[bootstrap] Installing dependencies from requirements.txt ...")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
        cwd=str(ROOT_DIR),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Dependency installation failed. Please check pip output above.")


def _ensure_runtime_paths() -> None:
    database_url = os.getenv("DATABASE_URL", "sqlite:///nuclei_webui.db")
    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:////"):
        db_rel_path = database_url.replace("sqlite:///", "", 1)
        db_file = ROOT_DIR / db_rel_path
        db_file.parent.mkdir(parents=True, exist_ok=True)


def _validate_frontend_assets() -> None:
    required_files = [
        ROOT_DIR / "backend" / "templates" / "base.html",
        ROOT_DIR / "backend" / "templates" / "login.html",
        ROOT_DIR / "backend" / "static" / "css" / "app.css",
    ]
    missing_assets = [str(path) for path in required_files if not path.exists()]
    if missing_assets:
        raise RuntimeError(
            "Required frontend assets are missing:\n- " + "\n- ".join(missing_assets)
        )


def main() -> None:
    _ensure_python_dependencies()

    from dotenv import load_dotenv

    load_dotenv()
    _ensure_runtime_paths()
    _validate_frontend_assets()

    from backend.app import create_app

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "1").lower() in {"1", "true", "yes", "on"}

    app = create_app()

    print("[startup] Nuclei WebUI is starting ...")
    print(f"[startup] Backend API + frontend are served together at http://127.0.0.1:{port}")
    print("[startup] Database engine initialization and schema checks are handled automatically.")

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
