import spacy
import sys
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any
import re
from .rules import (
    SensitivityLevel,
    REGEX_ID_PHYSICAL,
    REGEX_ID_MIGRATORY,
    REGEX_ID_JURIDICAL,
    REGEX_IBAN,
    REGEX_PHONE,
    REGEX_EMAIL,
    REGEX_IP,
    ANCHORS_HEALTH,
    ANCHORS_LEGAL,
    ANCHORS_CENSUS,
    WHITELIST_ROLES
)

@dataclass
class PIIFinding:
    entity_type: str        # e.g., 'NAME', 'ID_PHYSICAL', 'PHONE', 'DIAGNOSIS', 'EMAIL'
    value: str              # Original value
    start_char: int         # Start position (0-indexed)
    end_char: int           # End position (0-indexed)
    sensitivity_level: SensitivityLevel
    confidence: float       # Confidence score (0.0 to 1.0)
    context: str            # Snippet of surrounding text

    def to_json(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "sensitivity_level": self.sensitivity_level.value,
            "confidence": self.confidence,
            "context": self.context
        }

class CRDetector:
    def __init__(self, model_size: str = "lg"):
        self.model_name = f"es_core_news_{model_size}"
        self.nlp = self._load_spacy_model()

    def _load_spacy_model(self):
        try:
            return spacy.load(self.model_name)
        except IOError:
            print(f"[CRDetector] Model {self.model_name} not found. Downloading...")
            try:
                # Try downloading the requested model
                subprocess.run([sys.executable, "-m", "spacy", "download", self.model_name], check=True)
                return spacy.load(self.model_name)
            except Exception as e:
                print(f"[CRDetector] Failed to download {self.model_name}: {e}. Falling back to 'sm' model...")
                self.model_name = "es_core_news_sm"
                try:
                    return spacy.load(self.model_name)
                except IOError:
                    subprocess.run([sys.executable, "-m", "spacy", "download", self.model_name], check=True)
                    return spacy.load(self.model_name)

    def analyze(self, text: str) -> List[PIIFinding]:
        findings: List[PIIFinding] = []
        if not text:
            return findings

        # Process text with SpaCy
        doc = self.nlp(text)
        
        # 1. --- REGEX DETECTIONS (High priority / exact rules) ---
        findings.extend(self._detect_regex(text, REGEX_ID_PHYSICAL, "ID_PHYSICAL", SensitivityLevel.RESTRINGIDO, 1.0))
        findings.extend(self._detect_regex(text, REGEX_ID_MIGRATORY, "ID_MIGRATORY", SensitivityLevel.RESTRINGIDO, 1.0))
        findings.extend(self._detect_regex(text, REGEX_IBAN, "IBAN", SensitivityLevel.RESTRINGIDO, 1.0))
        findings.extend(self._detect_regex(text, REGEX_PHONE, "PHONE", SensitivityLevel.RESTRINGIDO, 0.95))
        findings.extend(self._detect_regex(text, REGEX_EMAIL, "EMAIL", SensitivityLevel.RESTRINGIDO, 1.0))
        findings.extend(self._detect_regex(text, REGEX_IP, "IP_ADDRESS", SensitivityLevel.RESTRINGIDO, 1.0))

        # We also detect juridical IDs so we can ignore any ORG that matches a juridical ID
        juridical_matches = self._detect_regex(text, REGEX_ID_JURIDICAL, "ID_JURIDICAL", SensitivityLevel.IRRESTRICTO, 1.0)
        juridical_spans = [(m.start_char, m.end_char) for m in juridical_matches]

        # 2. --- NLP / NER DETECTIONS (SpaCy) ---
        for ent in doc.ents:
            # Skip if this entity overlaps with a regex detection to avoid duplicates
            if self._is_overlapping(ent.start_char, ent.end_char, findings):
                continue
            
            # Skip if it is a corporate/juridical entity
            if ent.label_ == "ORG" or self._is_overlapping(ent.start_char, ent.end_char, juridical_matches):
                continue

            # Context snippet (100 chars around the entity)
            start_context = max(0, ent.start_char - 50)
            end_context = min(len(text), ent.end_char + 50)
            context_snippet = text[start_context:end_context].replace('\n', ' ')

            # A. PERSON ENTITIES
            if ent.label_ == "PER":
                # Check for whitelisted public roles right before the name
                context_before = text[max(0, ent.start_char - 20):ent.start_char].lower()
                is_public_role = any(role in context_before for role in WHITELIST_ROLES)
                
                if is_public_role:
                    # Functionary name - Irrestricto or skipped depending on policy.
                    # We report it as IRRESTRICTO with a lower priority
                    findings.append(PIIFinding(
                        entity_type="PUBLIC_OFFICIAL",
                        value=ent.text,
                        start_char=ent.start_char,
                        end_char=ent.end_char,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=0.8,
                        context=context_snippet
                    ))
                else:
                    # Regular private citizen name - IRRESTRICTO by default under Ley 8968, 
                    # but requires consent for commercial reuse
                    findings.append(PIIFinding(
                        entity_type="NAME",
                        value=ent.text,
                        start_char=ent.start_char,
                        end_char=ent.end_char,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=0.85,
                        context=context_snippet
                    ))

            # B. LOCATION ENTITIES
            elif ent.label_ == "LOC":
                # Detailed physical location - Restringido
                findings.append(PIIFinding(
                    entity_type="LOCATION",
                    value=ent.text,
                    start_char=ent.start_char,
                    end_char=ent.end_char,
                    sensitivity_level=SensitivityLevel.RESTRINGIDO,
                    confidence=0.8,
                    context=context_snippet
                ))

        # 3. --- HEURISTIC CONTEXTUAL INFERENCES (Health & Socio-economic status) ---
        # Scan text for medical symptoms/diagnoses and other sensitive data
        # We search for medical anchors and then capture nearby capitalised words or diagnostic terms
        findings.extend(self._infer_sensitive_context(text, ANCHORS_HEALTH, "DIAGNOSIS", SensitivityLevel.SENSIBLE))
        findings.extend(self._infer_sensitive_context(text, ANCHORS_CENSUS, "DEMOGRAPHIC", SensitivityLevel.RESTRINGIDO))

        # Sort findings by start_char
        findings.sort(key=lambda x: x.start_char)
        return findings

    def _detect_regex(self, text: str, regex: re.Pattern, entity_type: str, level: SensitivityLevel, confidence: float) -> List[PIIFinding]:
        results = []
        for match in regex.finditer(text):
            start, end = match.span()
            value = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            context = text[start_context:end_context].replace('\n', ' ')
            results.append(PIIFinding(
                entity_type=entity_type,
                value=value,
                start_char=start,
                end_char=end,
                sensitivity_level=level,
                confidence=confidence,
                context=context
            ))
        return results

    def _is_overlapping(self, start: int, end: int, existing: List[PIIFinding]) -> bool:
        for f in existing:
            # Check if intervals [start, end] and [f.start_char, f.end_char] overlap
            if max(start, f.start_char) < min(end, f.end_char):
                return True
        return False

    def _infer_sensitive_context(self, text: str, anchors: List[str], entity_type: str, level: SensitivityLevel) -> List[PIIFinding]:
        results = []
        text_lower = text.lower()
        for anchor in anchors:
            pattern = re.compile(rf'\b{re.escape(anchor)}\b')
            for match in pattern.finditer(text_lower):
                start_anchor, end_anchor = match.span()
                # Scan a window of 40 characters after the anchor to find specific terms (e.g. disease name or status)
                window_start = end_anchor
                window_end = min(len(text), end_anchor + 40)
                window_text = text[window_start:window_end]
                
                # Look for nouns or specific phrases (capitalized or specific keywords)
                # In medical context: "diagnóstico de Tuberculosis", "padece de Asma"
                # In census context: "vecino de Cartago", "profesión Abogado", "salario de 500000"
                words_match = re.search(r'\s*(?:de\s+|con\s+)?([A-ZÁÉÍÓÚÑa-záéíóúñ0-9]+(?:\s+[A-ZÁÉÍÓÚÑa-záéíóúñ0-9]+){0,2})', window_text)
                if words_match:
                    val = words_match.group(1).strip()
                    if not val or len(val) < 3:
                        continue
                    
                    # Compute coordinates in absolute text
                    start_val = window_start + window_text.find(val)
                    end_val = start_val + len(val)
                    
                    # Avoid duplicates
                    if self._is_overlapping(start_val, end_val, results):
                        continue
                        
                    start_context = max(0, start_val - 50)
                    end_context = min(len(text), end_val + 50)
                    context = text[start_context:end_context].replace('\n', ' ')
                    
                    # Adjust sensitivity for financial status (e.g. "salario" or "monto" -> SENSIBLE)
                    final_level = level
                    final_type = entity_type
                    if anchor in ["salario", "ingresos", "pobreza"]:
                        final_level = SensitivityLevel.SENSIBLE
                        final_type = "FINANCIAL_STATUS"
                    elif anchor in ["diagnóstico", "síntomas", "enfermedad", "padece"]:
                        final_type = "HEALTH_DATA"
                    
                    results.append(PIIFinding(
                        entity_type=final_type,
                        value=text[start_val:end_val],
                        start_char=start_val,
                        end_char=end_val,
                        sensitivity_level=final_level,
                        confidence=0.7,
                        context=context
                    ))
        return results
