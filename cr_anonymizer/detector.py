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
    REGEX_DATE,
    REGEX_COURT_CASE,
    REGEX_CREDIT_CARD,
    REGEX_AGE,
    REGEX_FINANCIAL_MONEY,
    ANCHORS_HEALTH,
    ANCHORS_LEGAL,
    ANCHORS_CENSUS,
    WHITELIST_ROLES,
    HEALTH_DISEASES_DB,
    HEALTH_MEDICINES_DB,
    WHITELIST_PUBLIC_ENTITIES,
    BELIEFS_RELIGIONS,
    BELIEFS_POLITICAL_UNIONS,
    ANCHORS_BIRTH,
    ANCHORS_ADDRESS,
    ANCHORS_DIRECTIONAL,
    ANCHORS_METRIC,
    ANCHORS_LANDMARK,
    KEYWORDS_SINPE
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

    def _normalize_text(self, txt: str) -> str:
        import unicodedata
        nfkd_form = unicodedata.normalize('NFKD', txt)
        return "".join([c for c in nfkd_form if not unicodedata.combining(c)]).lower()

    def _is_luhn_valid(self, digits: List[int]) -> bool:
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += doubled if doubled < 10 else doubled - 9
            else:
                checksum += digit
        return checksum % 10 == 0

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
        regex_findings.extend(self._detect_regex(text, REGEX_COURT_CASE, "COURT_CASE", SensitivityLevel.RESTRINGIDO, 1.0))
        regex_findings.extend(self._detect_regex(text, REGEX_AGE, "AGE", SensitivityLevel.RESTRINGIDO, 0.95))
        
        # Detectamos Cédulas Jurídicas para ignorarlas o marcarlas como Whitelist
        juridical_matches = self._detect_regex(text, REGEX_ID_JURIDICAL, "ID_JURIDICAL", SensitivityLevel.IRRESTRICTO, 1.0)
        regex_findings.extend(juridical_matches)

        # Fechas y clasificación DoB (Fecha de Nacimiento)
        date_findings = self._detect_regex(text, REGEX_DATE, "DATE", SensitivityLevel.IRRESTRICTO, 0.9)
        birth_anchors_pattern = re.compile(
            r'\b(?:nacimiento|nacer|nacido|nacida|natalicio|fec_nac|nacio)\b', 
            re.IGNORECASE
        )
        for df in date_findings:
            # Ventana de búsqueda de 30 caracteres antes de la fecha
            window_start = max(0, df.start_char - 30)
            preceding_text = text[window_start:df.start_char]
            if birth_anchors_pattern.search(self._normalize_text(preceding_text)):
                df.entity_type = "DATE_OF_BIRTH"
                df.sensitivity_level = SensitivityLevel.RESTRINGIDO
                df.confidence = 0.95
            regex_findings.append(df)

        # Tarjetas de crédito/débito con validación Luhn
        cc_matches = self._detect_regex(text, REGEX_CREDIT_CARD, "CREDIT_CARD", SensitivityLevel.SENSIBLE, 1.0)
        for cc in cc_matches:
            digits = [int(c) for c in cc.value if c.isdigit()]
            if self._is_luhn_valid(digits):
                regex_findings.append(cc)

        # Montos financieros
        money_matches = self._detect_regex(text, REGEX_FINANCIAL_MONEY, "MONEY", SensitivityLevel.IRRESTRICTO, 0.9)
        financial_anchors = re.compile(
            r'\b(?:salario|ingresos|ingreso|pensión|pension|deuda|monto|quiebra|pobreza|pagar|pago|costo|precio)\b',
            re.IGNORECASE
        )
        for mm in money_matches:
            # Ventana de búsqueda de 35 caracteres a los lados del monto
            window_start = max(0, mm.start_char - 35)
            window_end = min(len(text), mm.end_char + 35)
            surrounding = text[window_start:window_end]
            if financial_anchors.search(self._normalize_text(surrounding)):
                mm.entity_type = "FINANCIAL_STATUS"
                mm.sensitivity_level = SensitivityLevel.SENSIBLE
                mm.confidence = 0.9
                regex_findings.append(mm)

        # Clasificación SINPE Móvil
        sinpe_keywords_pattern = re.compile(
            r'\b(?:sinpe|pago móvil|pago movil|transferencia móvil|transferencia movil)\b', 
            re.IGNORECASE
        )
        for rf in regex_findings:
            if rf.entity_type == "PHONE":
                window_start = max(0, rf.start_char - 25)
                window_end = min(len(text), rf.end_char + 25)
                surrounding = text[window_start:window_end]
                if sinpe_keywords_pattern.search(self._normalize_text(surrounding)):
                    rf.entity_type = "SINPE_NUMBER"
                    rf.sensitivity_level = SensitivityLevel.RESTRINGIDO
                    rf.confidence = 0.95
        
        findings.extend(regex_findings)

        # 2. --- CAPA DE NLP / NER REFINADA ---
        ner_findings = self._refine_and_filter_ner(doc, regex_findings)
        findings.extend(ner_findings)

        # 3. --- CAPA HEURÍSTICA CONTEXTUAL BASADA EN TOKENS SINTÁCTICOS ---
        context_findings = self._infer_sensitive_context(doc)
        findings.extend(context_findings)

        # 4. --- CAPA DE BÚSQUEDA DIRECTA DE SALUD, CREENCIAS Y DIRECCIONES DESCRIPTIVAS ---
        lookup_findings = self._detect_token_lookups_and_addresses(doc)
        findings.extend(lookup_findings)

        # 5. --- CAPA DE BÚSQUEDA DIRECTA POR PALABRAS CLAVE (Robustez extra) ---
        direct_keyword_findings = self._detect_direct_keywords(text)
        findings.extend(direct_keyword_findings)

        # 6. --- RESOLUCIÓN FINAL DE TRASLAPES (CROSS-OVERLAP RESOLUTION) ---
        resolved_findings = self._resolve_overlaps(findings)
        
        # 7. --- FILTRADO DE TELÉFONOS FALSOS DENTRO DE CREDIT_CARDS ---
        cc_raw_spans = [match.span() for match in REGEX_CREDIT_CARD.finditer(text)]
        final_findings = []
        for f in resolved_findings:
            if f.entity_type == "PHONE":
                inside_cc = False
                for start, end in cc_raw_spans:
                    if f.start_char >= start and f.end_char <= end:
                        inside_cc = True
                        break
                if inside_cc:
                    continue
            final_findings.append(f)
            
        return final_findings

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
        
        # Ignorar localizaciones generales y palabras de transición comunes en español para evitar falsos positivos
        loc_ignore = {
            "costa rica", "cédula", "registro", "notaría", "tribunal", "provincia", 
            "cantón", "distrito", "además", "ademas", "también", "tambien", 
            "entonces", "como", "luego", "pero", "este", "esta", "ese", "esa", "aquel"
        }
        
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
                    
                    # Lista Blanca de Transparencia de Entidades Públicas
                    norm_ent_text = self._normalize_text(ent.text)
                    is_public_entity = any(pub in norm_ent_text for pub in WHITELIST_PUBLIC_ENTITIES)
                    
                    if is_public_entity:
                        ner_findings.append(PIIFinding(
                            entity_type="PUBLIC_ENTITY",
                            value=ent.text,
                            start_char=ent.start_char,
                            end_char=ent.end_char,
                            sensitivity_level=SensitivityLevel.IRRESTRICTO,
                            confidence=1.0,
                            context=context_snippet
                        ))
                    else:
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
            
            # Mitigación de Falsos Positivos de NLP: verbos conjugados al inicio de oración
            # ej. "Realizó un pago" -> "Realizó" no es una persona.
            first_token_pos = doc[ent.start_char // len(text) * len(doc)].pos_ if len(doc) > 0 else "NOUN"
            if text_lower in ["realizó", "realizo", "declaró", "declaro", "ingresó", "ingreso", "presentó", "presento", "además", "ademas"]:
                continue
                
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
                
                # Check for judicial conflict roles in context before the name
                judicial_roles_pattern = re.compile(
                    r'\b(?:imputado|imputada|querellado|querellada|acusado|acusada|denunciado|denunciada|condenado|condenada|reo|víctima|victima)\b',
                    re.IGNORECASE
                )
                is_judicial_role = judicial_roles_pattern.search(self._normalize_text(context_before))
                
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
                elif is_judicial_role:
                    ner_findings.append(PIIFinding(
                        entity_type="JUDICIAL_RECORD",
                        value=ent_clean_text,
                        start_char=ent_start,
                        end_char=ent_end,
                        sensitivity_level=SensitivityLevel.RESTRINGIDO,
                        confidence=0.9,
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
                
                # Si la localización coincide con una entidad pública, clasificar como PUBLIC_ENTITY
                norm_loc = self._normalize_text(ent.text)
                is_public = any(pub in norm_loc for pub in WHITELIST_PUBLIC_ENTITIES)
                if is_public:
                    ner_findings.append(PIIFinding(
                        entity_type="PUBLIC_ENTITY",
                        value=ent.text,
                        start_char=ent.start_char,
                        end_char=ent.end_char,
                        sensitivity_level=SensitivityLevel.IRRESTRICTO,
                        confidence=1.0,
                        context=context_snippet
                    ))
                else:
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

    def _detect_token_lookups_and_addresses(self, doc) -> List[PIIFinding]:
        results = []
        text = doc.text
        i = 0
        n_tokens = len(doc)
        
        while i < n_tokens:
            token = doc[i]
            token_norm = self._normalize_text(token.text)
            token_lemma_norm = self._normalize_text(token.lemma_)
            
            # --- 1. DIRECCIONES DESCRIPTIVAS ("Señas") ---
            if token_lemma_norm in ANCHORS_ADDRESS or token_norm in ANCHORS_ADDRESS:
                j = i + 1
                skipped = 0
                while j < n_tokens and doc[j].pos_ in ["ADP", "DET", "CCONJ"] and skipped < 4:
                    j += 1
                    skipped += 1
                
                accumulated_tokens = []
                allowed_pos = {"NOUN", "PROPN", "ADJ", "NUM", "ADP", "DET", "CCONJ"}
                
                while j < n_tokens and len(accumulated_tokens) < 15:
                    tok = doc[j]
                    if tok.text in [".", ";", "!", "?"] or "\n" in tok.text:
                        break
                    
                    tok_norm = self._normalize_text(tok.text)
                    if tok.pos_ in ["VERB", "AUX"] and tok_norm not in ANCHORS_LANDMARK:
                        break
                        
                    if tok.pos_ in allowed_pos or tok_norm in ANCHORS_LANDMARK or tok_norm in ANCHORS_DIRECTIONAL:
                        accumulated_tokens.append(tok)
                        j += 1
                    else:
                        break
                
                if accumulated_tokens:
                    while accumulated_tokens and accumulated_tokens[-1].pos_ in ["ADP", "CCONJ", "DET"]:
                        accumulated_tokens.pop()
                        
                    if accumulated_tokens:
                        start_char = accumulated_tokens[0].idx
                        end_char = accumulated_tokens[-1].idx + len(accumulated_tokens[-1].text)
                        addr_val = text[start_char:end_char]
                        
                        addr_norm = self._normalize_text(addr_val)
                        has_directional = any(d in addr_norm for d in ANCHORS_DIRECTIONAL)
                        has_metric = any(m in addr_norm for m in ANCHORS_METRIC)
                        has_landmark = any(l in addr_norm for l in ANCHORS_LANDMARK)
                        
                        if has_directional or has_metric or has_landmark:
                            start_context = max(0, start_char - 50)
                            end_context = min(len(text), end_char + 50)
                            context = text[start_context:end_context].replace('\n', ' ')
                            results.append(PIIFinding(
                                entity_type="RESIDENTIAL_ADDRESS",
                                value=addr_val,
                                start_char=start_char,
                                end_char=end_char,
                                sensitivity_level=SensitivityLevel.RESTRINGIDO,
                                confidence=0.85,
                                context=context
                            ))
                            i = j
                            continue
            i += 1
            
        return results

    def _detect_direct_keywords(self, text: str) -> List[PIIFinding]:
        # Búsqueda directa con expresiones regulares optimizadas para diccionarios estáticos
        results = []
        
        # 1. Enfermedades (HEALTH_DIAGNOSIS)
        diseases_pattern = re.compile(
            rf"\b(?:{'|'.join(re.escape(d) for d in HEALTH_DISEASES_DB)})\b", 
            re.IGNORECASE
        )
        for match in diseases_pattern.finditer(text):
            start, end = match.span()
            # Validar que no se trate de una palabra mal acentuada/slicing
            val = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            results.append(PIIFinding(
                entity_type="HEALTH_DIAGNOSIS",
                value=val,
                start_char=start,
                end_char=end,
                sensitivity_level=SensitivityLevel.SENSIBLE,
                confidence=0.95,
                context=text[start_context:end_context].replace('\n', ' ')
            ))

        # 2. Medicamentos (HEALTH_TREATMENT)
        medicines_pattern = re.compile(
            rf"\b(?:{'|'.join(re.escape(m) for m in HEALTH_MEDICINES_DB)})\b", 
            re.IGNORECASE
        )
        for match in medicines_pattern.finditer(text):
            start, end = match.span()
            val = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            results.append(PIIFinding(
                entity_type="HEALTH_TREATMENT",
                value=val,
                start_char=start,
                end_char=end,
                sensitivity_level=SensitivityLevel.SENSIBLE,
                confidence=0.95,
                context=text[start_context:end_context].replace('\n', ' ')
            ))

        # 3. Creencias Religiosas y Afiliaciones (SENSIBLE_BELIEFS)
        religions_pattern = re.compile(
            rf"\b(?:{'|'.join(re.escape(r) for r in BELIEFS_RELIGIONS)})\b", 
            re.IGNORECASE
        )
        for match in religions_pattern.finditer(text):
            start, end = match.span()
            val = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            results.append(PIIFinding(
                entity_type="SENSIBLE_BELIEFS",
                value=val,
                start_char=start,
                end_char=end,
                sensitivity_level=SensitivityLevel.SENSIBLE,
                confidence=0.9,
                context=text[start_context:end_context].replace('\n', ' ')
            ))

        political_pattern = re.compile(
            rf"\b(?:{'|'.join(re.escape(p) for p in BELIEFS_POLITICAL_UNIONS)})\b", 
            re.IGNORECASE
        )
        for match in political_pattern.finditer(text):
            start, end = match.span()
            val = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            results.append(PIIFinding(
                entity_type="SENSIBLE_BELIEFS",
                value=val,
                start_char=start,
                end_char=end,
                sensitivity_level=SensitivityLevel.SENSIBLE,
                confidence=0.9,
                context=text[start_context:end_context].replace('\n', ' ')
            ))

        # 4. Entidades Públicas Whitelisted (PUBLIC_ENTITY)
        public_entities_pattern = re.compile(
            rf"\b(?:{'|'.join(re.escape(e) for e in WHITELIST_PUBLIC_ENTITIES)})\b", 
            re.IGNORECASE
        )
        for match in public_entities_pattern.finditer(text):
            start, end = match.span()
            val = match.group(0)
            start_context = max(0, start - 50)
            end_context = min(len(text), end + 50)
            results.append(PIIFinding(
                entity_type="PUBLIC_ENTITY",
                value=val,
                start_char=start,
                end_char=end,
                sensitivity_level=SensitivityLevel.IRRESTRICTO,
                confidence=1.0,
                context=text[start_context:end_context].replace('\n', ' ')
            ))

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
                    # Priorizar el que tiene mayor especificidad
                    type_priority = {
                        "PUBLIC_OFFICIAL": 5,
                        "HEALTH_DIAGNOSIS": 4,
                        "HEALTH_TREATMENT": 4,
                        "FINANCIAL_STATUS": 4,
                        "CREDIT_CARD": 4,
                        "ID_PHYSICAL": 3,
                        "ID_MIGRATORY": 3,
                        "IBAN": 3,
                        "EMAIL": 3,
                        "PHONE": 3,
                        "SINPE_NUMBER": 3,
                        "COURT_CASE": 3,
                        "MARITAL_STATUS": 3,
                        "AGE": 3,
                        "DATE_OF_BIRTH": 3,
                        "SENSIBLE_BELIEFS": 3,
                        "NAME": 2,
                        "JUDICIAL_RECORD": 2,
                        "PUBLIC_ENTITY": 2,
                        "ORGANIZATION": 2,
                        "RESIDENTIAL_ADDRESS": 1,
                        "LOCATION": 1,
                        "DATE": 1,
                        "DEMOGRAPHIC": 1
                    }
                    f_prio = type_priority.get(f.entity_type, 0)
                    r_prio = type_priority.get(r.entity_type, 0)
                    
                    if f_prio > r_prio:
                        resolved.remove(r)
                        resolved.append(f)
                    break
            if not overlap:
                resolved.append(f)
                
        resolved.sort(key=lambda x: x.start_char)
        return resolved
