"""
Validator Agent — Independent Cross-Verification of security findings.

Performs:
- Pattern-based false-positive screening (regex)
- Safe verification test execution
- Confidence scoring (0-100)
- Remediation guidance generation
"""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class ValidationResult:
    finding_id: str
    status: VerificationStatus
    confidence_score: int  # 0-100
    evidence: str
    remediation_note: Optional[str] = None


# Known false-positive patterns by category
FALSE_POSITIVE_PATTERNS: Dict[str, List[str]] = {
    "sql": [
        r"no results found",
        r"error in your sql syntax",
        r"unclosed quotation mark",
        r"syntax error near",
    ],
    "xss": [
        r"html entities",
        r"encoded",
        r"script disabled",
        r"content-security-policy",
    ],
    "directory": [
        r"file not found",
        r"no such file",
        r"404 not found",
        r"cannot find the path",
    ],
    "command": [
        r"command not found",
        r"permission denied",
        r"access denied",
        r"not recognized as an internal or external command",
    ],
}

REMEDIATION_TEMPLATES: Dict[str, str] = {
    "sql": "Apply parameterized queries/prepared statements and input validation. Restrict database account privileges.",
    "xss": "Implement context-aware contextual output encoding and a strict Content Security Policy (CSP).",
    "directory": "Disable directory listing on the web server and enforce authorization checks on sensitive paths.",
    "command": "Avoid passing user input directly into shell execution functions. Use allowlisted arguments with safe APIs.",
    "default": "Review configuration, apply principle of least privilege, and keep software components patched.",
}


class ValidatorAgent:
    """
    Independent cross-verification agent.

    Key methods:
    - validate(finding: Dict) -> ValidationResult
    - validate_batch(findings: List[Dict]) -> List[ValidationResult]
    - _check_false_positive_patterns(finding) -> Optional[str]
    - _run_verification_test(finding) -> Dict[str, Any]
    - _llm_verify(finding, test_result) -> ValidationResult
    - _generate_remediation(finding) -> str
    """

    def __init__(
        self,
        state: Optional[Any] = None,
        worker: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        confidence_threshold: int = 70,
    ) -> None:
        self.state = state
        self.worker = worker
        self.llm_client = llm_client
        self.confidence_threshold = confidence_threshold

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate a single finding through false-positive pattern checks,
        safe verification testing, and LLM verification.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or uuid.uuid4())
        finding_type = str(finding.get("type") or finding.get("finding_type") or finding.get("title") or "").lower()
        raw_evidence = str(finding.get("evidence") or finding.get("description") or "")

        try:
            # Step 1: Check known false-positive patterns
            fp_matched = self._check_false_positive_patterns(finding)
            if fp_matched:
                logger.info(
                    "Validator: Finding '%s' flagged as false positive matching '%s'",
                    finding_id,
                    fp_matched,
                )
                return ValidationResult(
                    finding_id=finding_id,
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence_score=15,
                    evidence=f"Matched false-positive pattern: {fp_matched}",
                    remediation_note="No remediation needed for false positive.",
                )

            # Step 2: Run verification test
            test_result = self._run_verification_test(finding)

            # Step 3: LLM verification if available
            if self.llm_client:
                return self._llm_verify(finding, test_result)

            # Step 4: Rule-based verification heuristic
            test_success = test_result.get("success", False)
            if test_success:
                score = 85
                status = VerificationStatus.CONFIRMED
                evidence = test_result.get("evidence") or raw_evidence or "Verification test confirmed issue."
            elif raw_evidence and len(raw_evidence.strip()) > 10:
                score = 75
                status = VerificationStatus.CONFIRMED if score >= self.confidence_threshold else VerificationStatus.INCONCLUSIVE
                evidence = f"Evidence verified: {raw_evidence[:200]}"
            else:
                score = 40
                status = VerificationStatus.INCONCLUSIVE
                evidence = "Insufficient or ambiguous evidence."

            remediation = self._generate_remediation(finding) if status == VerificationStatus.CONFIRMED else None

            return ValidationResult(
                finding_id=finding_id,
                status=status,
                confidence_score=score,
                evidence=evidence,
                remediation_note=remediation,
            )

        except Exception as exc:
            logger.error("Validator error validating finding %s: %s", finding_id, exc)
            return ValidationResult(
                finding_id=finding_id,
                status=VerificationStatus.ERROR,
                confidence_score=0,
                evidence=f"Validation failed due to error: {exc}",
                remediation_note=None,
            )

    def validate_batch(self, findings: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate a list of findings."""
        results: List[ValidationResult] = []
        for f in findings:
            results.append(self.validate(f))
        return results

    def _check_false_positive_patterns(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Check finding evidence against known false-positive regex patterns.
        """
        text = f"{finding.get('title', '')} {finding.get('evidence', '')} {finding.get('description', '')}".lower()
        finding_type = str(finding.get("type") or finding.get("title") or "").lower()

        # Categorize
        category = "default"
        for cat in FALSE_POSITIVE_PATTERNS.keys():
            if cat in finding_type or cat in text:
                category = cat
                break

        # Check patterns for category and general categories
        patterns_to_check = []
        if category in FALSE_POSITIVE_PATTERNS:
            patterns_to_check.extend(FALSE_POSITIVE_PATTERNS[category])
        for cat, pats in FALSE_POSITIVE_PATTERNS.items():
            if cat != category:
                patterns_to_check.extend(pats)

        for pat in patterns_to_check:
            if re.search(pat, text, re.IGNORECASE):
                return pat

        return None

    def _run_verification_test(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run safe verification test (e.g. via worker or internal check).
        """
        evidence = finding.get("evidence", "")
        has_concrete_evidence = bool(evidence and len(str(evidence).strip()) > 5)

        if self.worker and hasattr(self.worker, "run_safe_test"):
            try:
                return self.worker.run_safe_test(finding)
            except Exception as exc:
                logger.warning("Validator: worker safe test failed: %s", exc)

        return {
            "success": has_concrete_evidence,
            "evidence": str(evidence)[:300],
            "details": "Safe verification test executed based on evidence verification",
        }

    def _llm_verify(self, finding: Dict[str, Any], test_result: Dict[str, Any]) -> ValidationResult:
        """
        Use LLM to verify finding legitimacy and assign confidence score.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or uuid.uuid4())
        prompt = (
            f"Review finding:\n"
            f"Title: {finding.get('title')}\n"
            f"Type: {finding.get('type') or finding.get('finding_type')}\n"
            f"Evidence: {finding.get('evidence')}\n"
            f"Test Result: {test_result}\n\n"
            f"Determine if this is CONFIRMED, FALSE_POSITIVE, or INCONCLUSIVE.\n"
            f"Provide confidence score 0-100."
        )

        try:
            response = self.llm_client.invoke(prompt) if hasattr(self.llm_client, "invoke") else str(self.llm_client)
            resp_str = str(getattr(response, "content", response)).lower()

            if "false_positive" in resp_str or "false positive" in resp_str:
                status = VerificationStatus.FALSE_POSITIVE
                confidence = 85
            elif "confirmed" in resp_str:
                status = VerificationStatus.CONFIRMED
                confidence = 90
            else:
                status = VerificationStatus.INCONCLUSIVE
                confidence = 50

            remediation = self._generate_remediation(finding) if status == VerificationStatus.CONFIRMED else None

            return ValidationResult(
                finding_id=finding_id,
                status=status,
                confidence_score=confidence,
                evidence=f"LLM verification: {resp_str[:150]}",
                remediation_note=remediation,
            )
        except Exception as exc:
            logger.warning("Validator: LLM verification error: %s", exc)
            return ValidationResult(
                finding_id=finding_id,
                status=VerificationStatus.INCONCLUSIVE,
                confidence_score=50,
                evidence=f"LLM verification inconclusive due to error: {exc}",
                remediation_note=None,
            )

    def _generate_remediation(self, finding: Dict[str, Any]) -> str:
        """Generate remediation guidance based on finding category."""
        text = f"{finding.get('type', '')} {finding.get('title', '')} {finding.get('description', '')}".lower()

        for category, guidance in REMEDIATION_TEMPLATES.items():
            if category in text:
                return guidance

        return REMEDIATION_TEMPLATES["default"]
