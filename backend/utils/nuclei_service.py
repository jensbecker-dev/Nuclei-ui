from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import Iterable


@dataclass
class NucleiResult:
    command: list[str]
    raw_output: str
    findings: list[dict]
    stderr: str
    return_code: int


class NucleiService:
    def __init__(self, binary: str = "nuclei") -> None:
        self.binary = binary

    def is_installed(self) -> bool:
        try:
            result = subprocess.run(
                [self.binary, "-version"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def get_version(self) -> str:
        result = subprocess.run(
            [self.binary, "-version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return "unbekannt"

        raw = (result.stdout or result.stderr or "").strip()
        cleaned = _strip_ansi(raw)

        # Prefer canonical version line when available
        for line in cleaned.splitlines():
            if "Nuclei Engine Version" in line:
                return line.strip()

        first_line = cleaned.splitlines()[0].strip() if cleaned else ""
        return first_line or "unbekannt"

    def discover_template_dirs(self) -> list[str]:
        dirs: list[str] = []
        env_path = os.getenv("NUCLEI_TEMPLATES")
        if env_path:
            dirs.append(env_path)
        dirs.append(os.path.expanduser("~/nuclei-templates"))

        existing = [d for d in dirs if os.path.isdir(d)]
        return existing

    def list_templates(self, limit: int = 200) -> list[str]:
        templates: list[str] = []
        for directory in self.discover_template_dirs():
            for root, _, files in os.walk(directory):
                for name in files:
                    if name.endswith(".yaml") or name.endswith(".yml"):
                        templates.append(os.path.join(root, name))
                        if len(templates) >= limit:
                            return templates
        return templates

    def build_command(
        self,
        target: str,
        template: str | None = None,
        severity: str | None = None,
        tags: str | None = None,
        advanced_args: str | None = None,
    ) -> list[str]:
        cmd = [self.binary, "-u", target, "-jsonl", "-silent", "-duc"]

        if template:
            cmd.extend(["-t", template])
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if advanced_args:
            cmd.extend(shlex.split(advanced_args))

        return cmd

    def run_scan(
        self,
        target: str,
        template: str | None = None,
        severity: str | None = None,
        tags: str | None = None,
        advanced_args: str | None = None,
    ) -> NucleiResult:
        command = self.build_command(
            target=target,
            template=template,
            severity=severity,
            tags=tags,
            advanced_args=advanced_args,
        )

        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        raw = proc.stdout or ""
        findings = self._parse_jsonl(raw)

        return NucleiResult(
            command=command,
            raw_output=raw,
            findings=findings,
            stderr=proc.stderr or "",
            return_code=proc.returncode,
        )

    @staticmethod
    def _parse_jsonl(raw: str) -> list[dict]:
        findings: list[dict] = []
        if not raw:
            return findings

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings


def summarize_by_severity(findings: Iterable[dict]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = (
            finding.get("info", {}).get("severity")
            if isinstance(finding.get("info"), dict)
            else None
        )
        severity_key = (severity or "info").lower()
        if severity_key not in summary:
            severity_key = "info"
        summary[severity_key] += 1
    return summary


def _strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)
