from typing import List, Dict, Callable
from .detector import PIIFinding
from .rules import SensitivityLevel

class CRAnonymizer:
    @staticmethod
    def anonymize(
        text: str,
        findings: List[PIIFinding],
        redact_levels: List[SensitivityLevel] = None,
        custom_replacer: Callable[[PIIFinding, int], str] = None
    ) -> str:
        """
        Replaces detected PII/sensitive entities in the original text.
        Processes findings in REVERSE order of start_char to prevent offset shifting.
        
        :param text: The original raw text.
        :param findings: A list of PIIFinding objects returned by CRDetector.
        :param redact_levels: Sensitivity levels to redact. If None, redacts SENSIBLE and RESTRINGIDO.
        :param custom_replacer: A callable function taking (finding, entity_counter) and returning a string replacement.
        :return: The anonymized/redacted text.
        """
        if not text or not findings:
            return text

        if redact_levels is None:
            # Default to redacting both Sensible and Restringido
            redact_levels = [SensitivityLevel.SENSIBLE, SensitivityLevel.RESTRINGIDO]

        # Filter findings that match the redact levels
        filtered_findings = [f for f in findings if f.sensitivity_level in redact_levels]

        # Sort in reverse order of start_char (right to left)
        sorted_findings = sorted(filtered_findings, key=lambda x: x.start_char, reverse=True)

        # Map to keep consistent names (e.g. "Juan Pérez" -> "[PERSONA_1]")
        # We need to compute counts in normal order first to make counters consistent
        normal_findings = sorted(filtered_findings, key=lambda x: x.start_char)
        person_map: Dict[str, str] = {}
        person_count = 1
        
        for f in normal_findings:
            if f.entity_type in ["NAME", "PUBLIC_OFFICIAL"]:
                if f.value not in person_map:
                    person_map[f.value] = f"[PERSONA_{person_count}]"
                    person_count += 1

        modified_text = text
        for f in sorted_findings:
            # Determine replacement string
            if custom_replacer:
                replacement = custom_replacer(f, person_count)
            else:
                # Default replacements
                if f.entity_type in ["NAME", "PUBLIC_OFFICIAL"] and f.value in person_map:
                    replacement = person_map[f.value]
                else:
                    replacement = f"[{f.entity_type}]"

            # Apply replacement using slicing
            modified_text = (
                modified_text[:f.start_char] +
                replacement +
                modified_text[f.end_char:]
            )
            
        return modified_text
