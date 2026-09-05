"""
Cleaner Agent — Parses and structures raw command output before storage.

Supports tool-specific parsers for nmap, gobuster, sqlmap, ffuf, curl,
and a generic fallback. Produces a normalized dict suitable for SQLite
and downstream agents.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Maximum characters of raw output to keep as preview
_RAW_PREVIEW_MAX = 500


class CleanerAgent:
    """
    Transforms raw tool output into structured, queryable data.
    Combines rule-based regex parsers with high-speed LLM cleaning (Groq)
    to eliminate banners, noise, and ANSI codes before saving to memory.

    Key methods:
    - clean(command, tool, raw_output, target, exit_code, duration) -> Dict[str, Any]
    - _llm_clean(tool, raw_output, target) -> Optional[Dict[str, Any]]
    - _parse_nmap(output, target) -> Dict[str, Any]
    - _parse_gobuster(output, target) -> Dict[str, Any]
    - _parse_sqlmap(output, target) -> Dict[str, Any]
    - _parse_ffuf(output, target) -> Dict[str, Any]
    - _parse_curl(output, target) -> Dict[str, Any]
    - _parse_generic(output, target) -> Dict[str, Any]
    - _generate_summary(parsed_data, tool) -> str
    - _extract_ports(parsed_data) -> str
    - _extract_vulnerabilities(parsed_data) -> str
    - _extract_directories(parsed_data) -> str
    """

    def __init__(self, use_llm: Optional[bool] = None) -> None:
        if use_llm is None:
            try:
                from watchtower.core.config import config
                self.use_llm = getattr(config, "cleaner_use_llm", True)
            except Exception:
                self.use_llm = True
        else:
            self.use_llm = use_llm

    def _format_list(self, item: Any) -> str:
        if not item:
            return ""
        if isinstance(item, list):
            return ",".join(str(x) for x in item if str(x).strip())
        return str(item)

    def _llm_clean(self, tool: str, raw_output: str, target: str) -> Optional[Dict[str, Any]]:
        """
        Use the LLM brain (e.g. Groq) to parse and distill raw tool logs into structured JSON.
        """
        if not raw_output or not raw_output.strip():
            return None

        try:
            from watchtower.agents.planner import get_llm
            from langchain_core.messages import HumanMessage

            llm = get_llm()
            if llm.__class__.__name__ == "MockLLM":
                return None

            sample_output = raw_output[:3500]
            prompt = (
                f"You are an expert security data cleaner.\n"
                f"Extract structured security information from the raw output of tool '{tool}' targeting '{target}'.\n"
                f"Remove terminal ANSI codes, banners, progress bars, and irrelevant verbose logs.\n\n"
                f"RAW OUTPUT:\n{sample_output}\n\n"
                f"Output strictly valid JSON with no markdown formatting:\n"
                f"{{\n"
                f'  "summary": "1-2 sentence executive summary of key discoveries or none",\n'
                f'  "open_ports": ["port/service", ...],\n'
                f'  "vulnerabilities": ["vulnerability name or CVE", ...],\n'
                f'  "directories": ["/path", ...],\n'
                f'  "key_data": {{ "extracted_fields": "values" }}\n'
                f"}}"
            )

            response = llm.invoke([HumanMessage(content=prompt)])
            content = getattr(response, "content", response)
            if isinstance(content, list):
                content = "".join(str(c) for c in content)
            content_str = str(content).strip()

            if content_str.startswith("```"):
                content_str = re.sub(r"^```(?:json)?\n?", "", content_str)
                content_str = re.sub(r"\n?```$", "", content_str)

            data = json.loads(content_str)
            logger.info("CleanerAgent: LLM cleaned output for '%s' successfully", tool)
            return data
        except Exception as exc:
            logger.debug("CleanerAgent: LLM clean skipped or failed: %s", exc)
            return None

    def clean(
        self,
        command: str,
        tool: str,
        raw_output: str,
        target: str,
        exit_code: int = 0,
        duration: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Clean and structure raw command output.

        Returns a dictionary with keys:
            command, tool, target, exit_code, duration, structured_output,
            clean_summary, open_ports, vulnerabilities, directories,
            raw_output_preview
        """
        tool_lower = (tool or "").lower().strip()

        parsers = {
            "nmap": self._parse_nmap,
            "gobuster": self._parse_gobuster,
            "sqlmap": self._parse_sqlmap,
            "ffuf": self._parse_ffuf,
            "curl": self._parse_curl,
        }

        parsed_data = None
        llm_result = None

        # If LLM cleaning is enabled, use LLM for generic tools or if regex produced no results
        if self.use_llm and tool_lower not in parsers:
            llm_result = self._llm_clean(tool, raw_output, target)

        if llm_result:
            parsed_data = llm_result.get("key_data") or llm_result
            clean_summary = llm_result.get("summary") or self._generate_summary(parsed_data, tool_lower)
            open_ports = self._format_list(llm_result.get("open_ports"))
            vulnerabilities = self._format_list(llm_result.get("vulnerabilities"))
            directories = self._format_list(llm_result.get("directories"))
        else:
            parser_fn = parsers.get(tool_lower, self._parse_generic)
            try:
                parsed_data = parser_fn(raw_output or "", target)
            except Exception as exc:
                logger.warning("CleanerAgent: parser for '%s' raised: %s", tool, exc)
                parsed_data = self._parse_generic(raw_output or "", target)

            clean_summary = self._generate_summary(parsed_data, tool_lower)
            open_ports = self._extract_ports(parsed_data)
            vulnerabilities = self._extract_vulnerabilities(parsed_data)
            directories = self._extract_directories(parsed_data)

        raw_preview = (raw_output or "")[:_RAW_PREVIEW_MAX]
        if len(raw_output or "") > _RAW_PREVIEW_MAX:
            raw_preview += "... (truncated)"

        result: Dict[str, Any] = {
            "command": command,
            "tool": tool,
            "target": target,
            "exit_code": exit_code,
            "duration": duration,
            "structured_output": json.dumps(parsed_data),
            "clean_summary": clean_summary,
            "open_ports": open_ports,
            "vulnerabilities": vulnerabilities,
            "directories": directories,
            "raw_output_preview": raw_preview,
        }

        logger.debug(
            "CleanerAgent: cleaned '%s' — ports=%s dirs=%s vulns=%s",
            tool, open_ports or "none", directories or "none", vulnerabilities or "none",
        )
        return result

    def _parse_nmap(self, output: str, target: str) -> Dict[str, Any]:
        """
        Extract open_ports: [{port, service}], host_up, total_open, os_guess.
        """
        open_ports: List[Dict[str, str]] = []
        host_up = False
        os_guess: Optional[str] = None

        for line in output.splitlines():
            line_stripped = line.strip()

            if "host is up" in line_stripped.lower():
                host_up = True

            port_match = re.match(
                r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$",
                line_stripped,
                re.IGNORECASE,
            )
            if port_match:
                port_num = port_match.group(1)
                protocol = port_match.group(2)
                service = port_match.group(3)
                version = port_match.group(4).strip() if port_match.group(4) else ""
                open_ports.append({
                    "port": f"{port_num}/{protocol}",
                    "service": service,
                    "version": version,
                })
                host_up = True

            os_match = re.match(r"^OS details:\s*(.+)$", line_stripped, re.IGNORECASE)
            if os_match:
                os_guess = os_match.group(1).strip()

        return {
            "open_ports": open_ports,
            "host_up": host_up,
            "total_open": len(open_ports),
            "os_guess": os_guess,
        }

    def _parse_gobuster(self, output: str, target: str) -> Dict[str, Any]:
        """
        Extract directories: [{path, status, size}], total_found.
        """
        directories: List[Dict[str, str]] = []

        for line in output.splitlines():
            line_stripped = line.strip()
            match = re.match(
                r"^(/\S*)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?",
                line_stripped,
            )
            if match:
                directories.append({
                    "path": match.group(1),
                    "status": match.group(2),
                    "size": match.group(3) or "",
                })

        return {
            "directories": directories,
            "total_found": len(directories),
        }

    def _parse_sqlmap(self, output: str, target: str) -> Dict[str, Any]:
        """
        Extract vulnerable, vulnerable_parameters, databases, evidence.
        """
        vulnerable = False
        vulnerable_parameters: List[str] = []
        databases: List[str] = []
        evidence_lines: List[str] = []

        for line in output.splitlines():
            line_lower = line.lower().strip()

            if "is vulnerable" in line_lower or "parameter:" in line_lower:
                param_match = re.search(r"parameter[:\s]+'?([^'(]+)", line, re.IGNORECASE)
                if param_match:
                    param = param_match.group(1).strip().rstrip(" (")
                    if param and param not in vulnerable_parameters:
                        vulnerable_parameters.append(param)
                vulnerable = True

            if any(k in line_lower for k in ("sql injection", "payload:", "type:")):
                if line.strip():
                    evidence_lines.append(line.strip())

            db_match = re.match(r"^\[[\*\+]\]\s+(.+)$", line.strip())
            if db_match and "available databases" not in line_lower:
                db_name = db_match.group(1).strip()
                if db_name and db_name not in databases:
                    databases.append(db_name)

        return {
            "vulnerable": vulnerable,
            "vulnerable_parameters": vulnerable_parameters,
            "databases": databases,
            "evidence": " | ".join(evidence_lines[:5]),
        }

    def _parse_ffuf(self, output: str, target: str) -> Dict[str, Any]:
        """
        Extract directories: [{path, status, size, words}], total_found.
        """
        directories: List[Dict[str, str]] = []

        for line in output.splitlines():
            line_stripped = line.strip()
            match = re.match(
                r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+)",
                line_stripped,
            )
            if match:
                directories.append({
                    "path": "/" + match.group(1).lstrip("/"),
                    "status": match.group(2),
                    "size": match.group(3),
                    "words": match.group(4),
                })

        return {
            "directories": directories,
            "total_found": len(directories),
        }

    def _parse_curl(self, output: str, target: str) -> Dict[str, Any]:
        """
        Extract status_code, headers, body_preview, body_length.
        """
        status_code: Optional[int] = None
        headers: Dict[str, str] = {}
        body_lines: List[str] = []
        in_body = False

        for line in output.splitlines():
            status_match = re.match(r"^[<>]?\s*HTTP/[\d.]+\s+(\d+)", line)
            if status_match:
                status_code = int(status_match.group(1))
                continue

            header_match = re.match(r"^<\s+([^:]+):\s*(.+)$", line)
            if header_match:
                headers[header_match.group(1).strip()] = header_match.group(2).strip()
                continue

            if line.strip() == "<":
                in_body = True
                continue

            if in_body:
                body_lines.append(line)

        body_text = "\n".join(body_lines)
        body_preview = body_text[:300] if body_text else ""

        return {
            "status_code": status_code,
            "headers": headers,
            "body_preview": body_preview,
            "body_length": len(body_text),
        }

    def _parse_generic(self, output: str, target: str) -> Dict[str, Any]:
        """
        Fallback parser for unknown tools.
        """
        lines = (output or "").splitlines()
        return {
            "line_count": len(lines),
            "char_count": len(output or ""),
            "preview": "\n".join(lines[:10]),
        }

    def _generate_summary(self, parsed_data: Dict[str, Any], tool: str) -> str:
        """Generate concise summary of parsed findings."""
        try:
            if tool == "nmap":
                ports = parsed_data.get("open_ports", [])
                total = parsed_data.get("total_open", 0)
                host_up = parsed_data.get("host_up", False)
                if not host_up:
                    return "Host appears down — no open ports discovered."
                if not ports:
                    return "Host is up but no open ports found."
                port_strs = [f"{p['port']}/{p['service']}" for p in ports[:5]]
                summary = f"Found {total} open port(s): {', '.join(port_strs)}"
                if total > 5:
                    summary += f" (+{total - 5} more)"
                return summary

            elif tool in ("gobuster", "ffuf"):
                total = parsed_data.get("total_found", 0)
                dirs = parsed_data.get("directories", [])
                if not dirs:
                    return "No directories or files discovered."
                examples = [d["path"] for d in dirs[:3]]
                summary = f"Found {total} path(s): {', '.join(examples)}"
                if total > 3:
                    summary += f" (+{total - 3} more)"
                return summary

            elif tool == "sqlmap":
                if parsed_data.get("vulnerable"):
                    params = ", ".join(parsed_data.get("vulnerable_parameters", []))
                    dbs = ", ".join(parsed_data.get("databases", []))
                    parts = [f"SQL injection found — parameters: {params or 'unknown'}"]
                    if dbs:
                        parts.append(f"databases: {dbs}")
                    return "; ".join(parts)
                return "No SQL injection vulnerabilities detected."

            elif tool == "curl":
                code = parsed_data.get("status_code", "?")
                length = parsed_data.get("body_length", 0)
                ct = parsed_data.get("headers", {}).get("Content-Type", "unknown")
                return f"HTTP {code} — Content-Type: {ct}, Body length: {length} bytes."

            else:
                lines = parsed_data.get("line_count", 0)
                chars = parsed_data.get("char_count", 0)
                return f"Generic output: {lines} lines, {chars} characters."

        except Exception as exc:
            logger.warning("CleanerAgent._generate_summary failed: %s", exc)
            return "Summary unavailable."

    def _extract_ports(self, parsed_data: Dict[str, Any]) -> str:
        """Extract comma-separated ports."""
        ports = parsed_data.get("open_ports", [])
        if not ports:
            return ""
        return ",".join(p.get("port", "").split("/")[0] for p in ports if p.get("port"))

    def _extract_vulnerabilities(self, parsed_data: Dict[str, Any]) -> str:
        """Extract comma-separated vulnerability labels."""
        params = parsed_data.get("vulnerable_parameters", [])
        if params:
            return ",".join(params)
        if parsed_data.get("vulnerable"):
            return "sql_injection"
        return ""

    def _extract_directories(self, parsed_data: Dict[str, Any]) -> str:
        """Extract comma-separated directories."""
        dirs = parsed_data.get("directories", [])
        if not dirs:
            return ""
        return ",".join(d.get("path", "") for d in dirs if d.get("path"))
