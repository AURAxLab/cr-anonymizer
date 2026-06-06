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
    entity_type: str        # e.g., 'NAME', 'ID_PHYSICAL', 'PHONE', 'HEALTH_DATA', 'EMAIL'
    value: str              # Valor original
    start_char: int         # Posición de inicio (0-indexed)
    end_char: int           # Posición de fin (0-indexed)
    sensitivity_level: SensitivityLevel
    confidence: float       # Confianza del detector (0.0 a 1.0)
    context: str            # Fragmento de texto circundante

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
    def __init__(self, model_size: str = "sm"):
        # Se prefiere el modelo pequeño 'sm' para rapidez y compatibilidad,
        # pero con nuestro motor de reglas híbrido logramos una altísima precisión.
        self.model_name = f"es_core_news_{model_size}"
        self.nlp = self._load_spacy_model()

    def _load_spacy_model(self):
        try:
            return spacy.load(self.model_name)
        except IOError:
            print(f"[CRDetector] Modelo {self.model_name} no encontrado. Descargando...")
            try:
                subprocess.run([sys.executable, "-m", "spacy", "download", self.model_name], check=True)
                return spacy.load(self.model_name)
            except Exception as e:
                print(f"[CRDetector] Error al descargar {self.model_name}: {e}. Usando 'sm' como fallback...")
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

        # Procesar texto con SpaCy (obtiene POS, Lematización y Dependencias)
        doc = self.nlp(text)
        
        # 1. --- CAPA DE EXPRESIONES REGULARES (Prioridad Alta) ---
        regex_findings = []
        regex_findings.extend(self._detect_regex(text, REGEX_ID_PHYSICAL, "ID_PHYSICAL", SensitivityLevel.RESTRINGIDO, 1.0))
        regex_findings.extend(self._detect_regex(text, REGEX_ID_MIGRATORY, "ID_MIGRATORY", SensitivityLevel.RESTRINGIDO, 1.0))
        regex_findings.extend(self._detect_regex(text, REGEX_IBAN, "IBAN", SensitivityLevel.RESTRINGIDO, 1.0))
        regex_findings.extend(self._detect_regex(text, REGEX_PHONE, "PHONE", SensitivityLevel.RESTRINGIDO, 0.95))
        regex_findings.extend(self._detect_regex(text, REGEX_EMAIL, "EMAIL", SensitivityLevel.RESTRINGIDO, 1.0))
        regex_findings.extend(self._detect_regex(text, REGEX_IP, "IP_ADDRESS", SensitivityLevel.RESTRINGIDO, 1.0))
        
        # Detectamos Cédulas Jurídicas para ignorarlas o marcarlas como IRRESTRICTO
        juridical_matches = self._detect_regex(text, REGEX_ID_JURIDICAL, "ID_JURIDICAL", SensitivityLevel.IRRESTRICTO, 1.0)
        regex_findings.extend(juridical_matches)
        
        findings.extend(regex_findings)

        # 2. --- CAPA DE NLP / NER REFINADA ---
        ner_findings = self._refine_and_filter_ner(doc, regex_findings)
        findings.extend(ner_findings)

        # 3. --- CAPA HEURÍSTICA CONTEXTUAL BASADA EN TOKENS SINTÁCTICOS ---
        context_findings = self._infer_sensitive_context(doc)
        findings.extend(context_findings)

        # 4. --- RESOLUCIÓN FINAL DE TRASLAPES (CROSS-OVERLAP RESOLUTION) ---
        resolved_findings = self._resolve_overlaps(findings)
        
        return resolved_findings

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
            if max(start, f.start_char) < min(end, f.end_char):
                return True
        return False

    def _refine_and_filter_ner(self, doc, regex_findings: List[PIIFinding]) -> List[PIIFinding]:
        ner_findings = []
        text = doc.text
        
        role_whitelist = [r.lower() for r in WHITELIST_ROLES]
        honorifics = [
            "dr.", "dra.", "lic.", "licda.", "don", "doña", "señor", "señora", 
            "notario", "notaria", "alcalde", "alcaldesa", "paciente", "pacienta"
        ]
        org_keywords = ["tribunal", "registro", "corporación", "sociedad", "ministerio", "s.a.", "limitada", "cooperativa", "municipalidad"]
        title_modifiers = ["pública", "público", "electoral", "supremo", "civil", "penal", "laboral", "de"]
        
        # Limpieza de sets para búsquedas exactas sin puntuación
        role_whitelist_clean = {re.sub(r'[^\wÁÉÍÓÚÑa-záéíóúñ]', '', r).lower() for r in role_whitelist}
        honorifics_clean = {re.sub(r'[^\wÁÉÍÓÚÑa-záéíóúñ]', '', h).lower() for h in honorifics}
        title_modifiers_clean = {re.sub(r'[^\wÁÉÍÓÚÑa-záéíóúñ]', '', m).lower() for m in title_modifiers}
        
        # Ignorar localizaciones generales para evitar falsos positivos de redacción
        loc_ignore = {"costa rica", "cédula", "registro", "notaría", "tribunal", "provincia", "cantón", "distrito"}
        
        # 1. Filtrar traslapes de expresiones regulares y localizaciones ignoradas antes de fusionar
        filtered_ents = []
        for ent in doc.ents:
            if self._is_overlapping(ent.start_char, ent.end_char, regex_findings):
                continue
            if ent.text.lower() in loc_ignore:
                continue
            filtered_ents.append(ent)
            
        # 2. Fusionar entidades SpaCy contiguas que representen nombres o cargos (separadas solo por espacio/puntuación)
        merged_ents = []
        i = 0
        while i < len(filtered_ents):
            ent = filtered_ents[i]
            
            while i + 1 < len(filtered_ents):
                next_ent = filtered_ents[i + 1]
                gap = text[ent.end_char:next_ent.start_char]
                
                # Si la brecha consiste únicamente en espacios o signos de puntuación menores
                if re.match(r'^[\s,.:;]*$', gap):
                    new_text = text[ent.start_char:next_ent.end_char]
                    new_label = ent.label_ if ent.label_ == next_ent.label_ else "MISC"
                    
                    class MockEnt:
                        def __init__(self, text, label, start_char, end_char):
                            self.text = text
                            self.label_ = label
                            self.start_char = start_char
                            self.end_char = end_char
                            
                    ent = MockEnt(new_text, new_label, ent.start_char, next_ent.end_char)
                    i += 1
                    continue
                break
                
            merged_ents.append(ent)
            i += 1
        
        # 3. Procesar las entidades (fusionadas o individuales)
        for ent in merged_ents:
            text_lower = ent.text.lower()
            
            # A. Identificar si es una Organización / Institución Pública
            if ent.label_ in ["ORG", "LOC", "MISC"]:
                is_org = ent.label_ == "ORG" or any(kw in text_lower for kw in org_keywords)
                if is_org:
                    start_context = max(0, ent.start_char - 50)
                    end_context = min(len(text), ent.end_char + 50)
                    context_snippet = text[start_context:end_context].replace('\n', ' ')
                    ner_findings.append(PIIFinding(
                        entity_type="ORGANIZATION",
                        value=ent.text,
                        start_char=ent.start_char,
                        end_char=ent.end_char,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=0.8,
                        context=context_snippet
                    ))
                    continue

            # B. Identificar si representa a una Persona
            is_person = ent.label_ == "PER"
            matched_role = None
            
            # Analizar el contexto previo al token de la entidad (hasta 25 caracteres antes)
            context_before = text[max(0, ent.start_char - 25):ent.start_char].lower()
            
            # Limpiar artículos iniciales en la entidad
            articles_pattern = re.compile(r'^(el|la|los|las|un|una|del|al)\s+', re.IGNORECASE)
            ent_clean_text = articles_pattern.sub('', ent.text)
            ent_start = ent.start_char + (len(ent.text) - len(ent_clean_text))
            ent_end = ent.end_char
            
            # 1. Buscar cargos y honoríficos dentro del propio texto de la entidad
            for role in role_whitelist + honorifics:
                pattern = re.compile(rf'\b{re.escape(role)}\b', re.IGNORECASE)
                match = pattern.search(ent_clean_text)
                if match:
                    is_person = True
                    w_clean = re.sub(r'[^\wÁÉÍÓÚÑa-záéíóúñ]', '', role).lower()
                    if w_clean in role_whitelist_clean:
                        matched_role = role
                    
                    # Si el rol/honorífico está al principio, limpiar prefijo y adjetivos de cargo
                    if match.start() < len(ent_clean_text) / 2:
                        prefix_end = match.end()
                        remaining = ent_clean_text[prefix_end:]
                        
                        # Limpiar secuencialmente otros roles, honoríficos y modificadores (ej. "Pública")
                        words = remaining.split()
                        clean_words = []
                        stripping = True
                        for w in words:
                            w_clean = re.sub(r'[^\wÁÉÍÓÚÑa-záéíóúñ]', '', w).lower()
                            if stripping and (w_clean in role_whitelist_clean or w_clean in honorifics_clean or w_clean in title_modifiers_clean or not w[0].isupper()):
                                continue
                            else:
                                stripping = False
                                clean_words.append(w)
                        
                        name_part = " ".join(clean_words)
                        if name_part:
                            offset_diff = ent_clean_text.find(name_part)
                            if offset_diff > 0:
                                ent_clean_text = name_part
                                ent_start = ent_start + offset_diff
                                ent_end = ent_start + len(name_part)
                    break
            
            # 2. Verificar roles u honoríficos en el contexto previo
            for role in role_whitelist:
                pattern = re.compile(rf'\b{re.escape(role)}\b', re.IGNORECASE)
                if pattern.search(context_before):
                    is_person = True
                    matched_role = role
                    break
            
            if not matched_role:
                for hon in honorifics:
                    pattern = re.compile(rf'\b{re.escape(hon)}\b', re.IGNORECASE)
                    if pattern.search(context_before):
                        is_person = True
                        break
            
            if "paciente" in context_before or "paciente" in ent.text.lower():
                is_person = True

            if is_person:
                # Validar que no se trate de una enfermedad mal clasificada
                if ent_clean_text.lower() in ["tuberculosis", "asma", "cáncer", "diabetes", "vih", "sida"]:
                    continue
                    
                start_context = max(0, ent_start - 50)
                end_context = min(len(text), ent_end + 50)
                context_snippet = text[start_context:end_context].replace('\n', ' ')
                
                if matched_role:
                    ner_findings.append(PIIFinding(
                        entity_type="PUBLIC_OFFICIAL",
                        value=ent_clean_text,
                        start_char=ent_start,
                        end_char=ent_end,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=0.85,
                        context=context_snippet
                    ))
                else:
                    ner_findings.append(PIIFinding(
                        entity_type="NAME",
                        value=ent_clean_text,
                        start_char=ent_start,
                        end_char=ent_end,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=0.85,
                        context=context_snippet
                    ))
                continue

            # C. Identificar Localizaciones
            if ent.label_ == "LOC":
                start_context = max(0, ent.start_char - 50)
                end_context = min(len(text), ent.end_char + 50)
                context_snippet = text[start_context:end_context].replace('\n', ' ')
                ner_findings.append(PIIFinding(
                    entity_type="LOCATION",
                    value=ent.text,
                    start_char=ent.start_char,
                    end_char=ent.end_char,
                    sensitivity_level=SensitivityLevel.RESTRINGIDO,
                    confidence=0.8,
                    context=context_snippet
                ))

        return ner_findings

    def _is_valid_context_token(self, token, common_spanish_verbs) -> bool:
        pos = token.pos_
        text_lower = token.text.lower()
        if pos in ["NOUN", "PROPN", "ADJ", "NUM"]:
            return True
        if pos in ["VERB", "AUX"]:
            if text_lower in common_spanish_verbs:
                return False
            if text_lower.endswith(("ar", "er", "ir", "ando", "iendo", "ado", "ido")):
                return True
            return False
        return False

    def _infer_sensitive_context(self, doc) -> List[PIIFinding]:
        results = []
        text = doc.text
        
        # Mapear anclas a conjuntos de búsqueda
        health_anchors = {a.lower() for a in ANCHORS_HEALTH}
        census_anchors = {a.lower() for a in ANCHORS_CENSUS}
        
        i = 0
        while i < len(doc):
            token = doc[i]
            token_text_lower = token.text.lower()
            
            # Caso especial: Estado civil (auto-contenido, no requiere escanear hacia adelante)
            if token_text_lower in ["soltero", "soltera", "casado", "casada", "divorciado", "divorciada", "viudo", "viuda"]:
                results.append(PIIFinding(
                    entity_type="MARITAL_STATUS",
                    value=token.text,
                    start_char=token.idx,
                    end_char=token.idx + len(token.text),
                    sensitivity_level=SensitivityLevel.IRRESTRICTO,
                    confidence=0.9,
                    context=text[max(0, token.idx - 50):min(len(text), token.idx + len(token.text) + 50)].replace('\n', ' ')
                ))
                i += 1
                continue
                
            target_type = None
            level = None
            
            if token_text_lower in health_anchors:
                target_type = "HEALTH_DATA"
                level = SensitivityLevel.SENSIBLE
            elif token_text_lower in census_anchors:
                target_type = "DEMOGRAPHIC"
                level = SensitivityLevel.RESTRINGIDO
                
            if target_type:
                # Encontramos un ancla. Buscaremos tokens hacia adelante para extraer el valor exacto
                j = i + 1
                
                # Omitir palabras de enlace y verbos comunes/auxiliares
                introductory_pos = ["ADP", "DET"]
                introductory_words = [
                    "de", "con", "el", "la", "un", "una", "del", "al", "en", "para", "por", 
                    "que", "tener", "declara", "ingresó", "presentando", "confirma"
                ]
                while j < len(doc) and (doc[j].pos_ in introductory_pos or doc[j].text.lower() in introductory_words):
                    if j - i > 4:  # Limitar omisión
                        break
                    j += 1
                
                # Acumular tokens sustantivos, adjetivos y números
                accumulated_tokens = []
                common_spanish_verbs = {
                    "ir", "ser", "estar", "haber", "tener", "hacer", "decir", "poder", "dar", 
                    "ver", "querer", "saber", "llegar", "pasar", "deber", "poner", "parecer", 
                    "quedar", "creer", "hablar", "llevar", "dejar", "ordenar", "confirmar", 
                    "declarar", "ingresar", "presentar", "compara", "comparecer", "transferir", 
                    "pactar", "anunciar", "defender", "asistir", "declara", "declaró", "ingresó", 
                    "confirma", "confirmó", "ordena", "ordenó", "presenta", "presentó", "tiene", 
                    "cuenta", "asistieron", "anunció", "defendió", "transfiere", "pacta", "comparece"
                }
                
                while j < len(doc):
                    next_tok = doc[j]
                    text_lower = next_tok.text.lower()
                    
                    if self._is_valid_context_token(next_tok, common_spanish_verbs):
                        accumulated_tokens.append(next_tok)
                        j += 1
                    elif next_tok.pos_ in ["ADP", "CCONJ"] and text_lower in ["de", "con", "y", "o", "e", "del"]:
                        # Permitir enlaces si continúan con un token válido
                        if j + 1 < len(doc) and self._is_valid_context_token(doc[j+1], common_spanish_verbs):
                            accumulated_tokens.append(next_tok)
                            accumulated_tokens.append(doc[j+1])
                            j += 2
                        else:
                            break
                    else:
                        break
                
                if accumulated_tokens:
                    # Eliminar enlaces huérfanos al final
                    while accumulated_tokens and accumulated_tokens[-1].pos_ in ["ADP", "CCONJ"]:
                        accumulated_tokens.pop()
                        
                    if accumulated_tokens:
                        start_char = accumulated_tokens[0].idx
                        end_char = accumulated_tokens[-1].idx + len(accumulated_tokens[-1].text)
                        value = text[start_char:end_char]
                        
                        # Omitir si es un adjetivo general solitario
                        if len(accumulated_tokens) == 1 and accumulated_tokens[0].pos_ == "ADJ":
                            i += 1
                            continue
                            
                        anchor_origin = token_text_lower
                        
                        # Si son sustantivos propios tras "vecino de" o "paciente", o son puramente sustantivos propios
                        is_all_propn = all(t.pos_ == "PROPN" for t in accumulated_tokens)
                        if is_all_propn or (anchor_origin in ["paciente", "vecino", "vecino de"] and any(t.pos_ == "PROPN" for t in accumulated_tokens)):
                            # Si es un nombre propio tras "vecino de", es una ubicación. Si es tras "paciente", es un nombre.
                            if anchor_origin in ["vecino", "vecino de"]:
                                target_type = "LOCATION"
                                level = SensitivityLevel.RESTRINGIDO
                            else:
                                target_type = "NAME"
                                level = SensitivityLevel.IRRESTRICTO
                        elif anchor_origin in ["salario", "ingresos", "pobreza"]:
                            target_type = "FINANCIAL_STATUS"
                            level = SensitivityLevel.SENSIBLE
                            
                        start_context = max(0, start_char - 50)
                        end_context = min(len(text), end_char + 50)
                        context = text[start_context:end_context].replace('\n', ' ')
                        
                        results.append(PIIFinding(
                            entity_type=target_type,
                            value=value,
                            start_char=start_char,
                            end_char=end_char,
                            sensitivity_level=level,
                            confidence=0.75,
                            context=context
                        ))
            i += 1
            
        return results

    def _resolve_overlaps(self, findings: List[PIIFinding]) -> List[PIIFinding]:
        if not findings:
            return []
            
        # Ordenar por start_char (ascendente) y luego por longitud de span (descendente)
        findings = sorted(findings, key=lambda x: (x.start_char, -(x.end_char - x.start_char)))
        
        resolved = []
        for f in findings:
            overlap = False
            for r in resolved:
                if max(f.start_char, r.start_char) < min(f.end_char, r.end_char):
                    overlap = True
                    # Si tienen exactamente las mismas coordenadas o se traslapan, decidir según tipo y confianza
                    # Priorizar el que tiene mayor especificidad
                    type_priority = {
                        "PUBLIC_OFFICIAL": 5,
                        "HEALTH_DATA": 4,
                        "FINANCIAL_STATUS": 4,
                        "ID_PHYSICAL": 3,
                        "ID_MIGRATORY": 3,
                        "IBAN": 3,
                        "EMAIL": 3,
                        "PHONE": 3,
                        "MARITAL_STATUS": 3,
                        "NAME": 2,
                        "LOCATION": 1,
                        "DEMOGRAPHIC": 1
                    }
                    f_prio = type_priority.get(f.entity_type, 0)
                    r_prio = type_priority.get(r.entity_type, 0)
                    
                    # Si f tiene mayor especificidad que r, reemplazamos r por f
                    if f_prio > r_prio:
                        resolved.remove(r)
                        resolved.append(f)
                    break
            if not overlap:
                resolved.append(f)
                
        resolved.sort(key=lambda x: x.start_char)
        return resolved
