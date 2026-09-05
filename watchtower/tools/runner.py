import logging
import os
import subprocess
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


def run_cli_tool(
    command: List[str],
    timeout: int = 300,
    auth_metadata: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> str:
    """
    Executes a CLI tool safely with timeout, argument sanitization, auth injection, and smart truncation.
    """
    if "timeout" in kwargs and kwargs["timeout"]:
        try:
            timeout = int(kwargs["timeout"])
        except (ValueError, TypeError):
            pass

    # Guard against command injection and control characters
    dangerous_chars = [";", "&", "|", "`", "$", "\x00", "\n", "\r"]
    for arg in command:
        if any(c in arg for c in dangerous_chars):
            err_msg = f"Command argument validation failed: prohibited character detected in '{arg}'"
            logger.error(err_msg)
            return f"Error executing tool: {err_msg}"

    # Inject auth headers/cookies if provided
    if auth_metadata:
        for key, val in auth_metadata.items():
            if len(command) > 0 and ("httpx" in command[0] or "curl" in command[0]):
                command.extend(["-H", f"{key}: {val}"])
            elif len(command) > 0 and "sqlmap" in command[0]:
                if key.lower() == "cookie":
                    command.extend(["--cookie", str(val)])
                else:
                    command.extend(["--headers", f"{key}: {val}"])

    logger.info("Running command: %s (timeout=%ds)", " ".join(command), timeout)

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
        stdout, stderr = proc.communicate(timeout=timeout)

        output = stdout or ""
        if stderr:
            output += f"\nStderr: {stderr}"

        # Preserve rich tool outputs for CleanerAgent (up to 30,000 chars)
        if len(output) > 30000:
            keywords = [
                "vulnerability", "critical", "high", "medium", "low",
                "[+]", "finding", "exposed", "error", "warning",
                "open", "cve-", "status: 200", "status: 301", "status: 403",
            ]
            lines = output.splitlines()
            important_lines = [l for l in lines if any(k in l.lower() for k in keywords)]

            if len(important_lines) > 50:
                truncated = "\n".join(important_lines[:150]) + "\n...[TRUNCATED - Showing Important Hits Only]"
            else:
                truncated = output[:15000] + "\n...[TRUNCATED MIDDLE]...\n" + output[-15000:]

            return truncated

        return output

    except subprocess.TimeoutExpired:
        if proc:
            try:
                proc.kill()
                proc.communicate()
            except Exception:
                pass
        err_msg = f"Tool execution timed out after {timeout} seconds: {' '.join(command)}"
        logger.error(err_msg)
        return f"Error executing tool: {err_msg}"
    except Exception as e:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        err_msg = f"Error executing tool {' '.join(command)}: {e}"
        logger.error(err_msg)
        return err_msg
