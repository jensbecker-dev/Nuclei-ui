"""Standalone helper API for Nuclei scans.

Uses the shared backend Nuclei service so CLI and WebUI stay aligned.
"""

from __future__ import annotations

import argparse
import json
import sys

from backend.utils.nuclei_service import NucleiService


class NucleiAPI:
    def __init__(self, binary: str = "nuclei") -> None:
        self.service = NucleiService(binary=binary)
        if not self.service.is_installed():
            raise EnvironmentError("Nuclei is not installed. Please install it to use the API.")

    def run_scan(
        self,
        target: str,
        template: str | None = None,
        severity: str | None = None,
        tags: str | None = None,
        advanced_args: str | None = None,
    ) -> dict:
        result = self.service.run_scan(
            target=target,
            template=template,
            severity=severity,
            tags=tags,
            advanced_args=advanced_args,
        )
        return {
            "command": result.command,
            "returnCode": result.return_code,
            "stderr": result.stderr,
            "findingsCount": len(result.findings),
            "findings": result.findings,
            "rawOutput": result.raw_output,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nuclei API")
    parser.add_argument("--target", required=True, help="Target URL for the scan")
    parser.add_argument("--template", help="Template file for the scan")
    parser.add_argument("--severity", help="Severity filter, e.g. critical,high")
    parser.add_argument("--tags", help="Tag filter, e.g. cve,rce")
    parser.add_argument("--advanced-args", help="Additional raw Nuclei flags")
    parser.add_argument("--binary", default="nuclei", help="Path to nuclei binary")
    args = parser.parse_args()

    api = NucleiAPI(binary=args.binary)
    scan_result = api.run_scan(
        target=args.target,
        template=args.template,
        severity=args.severity,
        tags=args.tags,
        advanced_args=args.advanced_args,
    )
    json.dump(scan_result, sys.stdout, indent=2)
    print()