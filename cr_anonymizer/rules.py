import re
from enum import Enum

class SensitivityLevel(str, Enum):
    SENSIBLE = "SENSIBLE"
    RESTRINGIDO = "RESTRINGIDO"
    IRRESTRICTO = "IRRESTRICTO"

# --- Expresiones Regulares Costarricenses ---

# Cédula Física costarricense (9 dígitos: formato X-XXXX-XXXX o X XXXX XXXX o XXXXXX)
# El primer número (provincia/tomo) va del 1 al 9.
REGEX_ID_PHYSICAL = re.compile(r'\b[1-9]-\d{4}-\d{4}\b|\b[1-9]\s\d{4}\s\d{4}\b|\b[1-9]\d{8}\b')

# DIMEX (Identificación de Extranjeros en CR: 11 o 12 dígitos)
# Formato: 11 o 12 dígitos consecutivos o separados por guiones/espacios
REGEX_ID_MIGRATORY = re.compile(r'\b\d{11,12}\b|\b\d{3}-\d{4}-\d{4,5}\b')

# Cédula Jurídica (10 dígitos: formato X-XXX-XXXXXX, ej. 3-101-123456 o 3101123456)
REGEX_ID_JURIDICAL = re.compile(r'\b[1-9]-\d{3}-\d{6}\b|\b[1-9]\d{9}\b')

# Cuentas IBAN costarricenses (Comienzan con CR y 20 dígitos)
REGEX_IBAN = re.compile(r'\bCR\d{20}\b', re.IGNORECASE)

# Teléfonos costarricenses (8 dígitos, inician con 2, 4, 5, 6, 7 o 8)
# Formato: XXXX-XXXX, XXXX XXXX o XXXXXXXX
REGEX_PHONE = re.compile(r'\b[245678]\d{3}-\d{4}\b|\b[245678]\d{3}\s\d{4}\b|\b[245678]\d{7}\b')

# Correos Electrónicos
REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Direcciones IP
REGEX_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# --- Diccionarios de Anclas de Contexto y Listas Blancas ---

# Anclas para contextualizar y refinar el tipo de dato
ANCHORS_HEALTH = [
    "paciente", "diagnóstico", "sintomatología", "padece", "padece de", "sufre de",
    "enfermedad", "diagnostica", "diagnosticado", "recetado", "medicamento",
    "tratamiento", "expediente clínico", "clínico", "síntomas", "patológico",
    "médico", "cirugía", "hospitalizado", "lesión", "patología"
]

ANCHORS_LEGAL = [
    "actor", "demandado", "imputado", "delito", "víctima", "testigo", "causa",
    "querella", "ofendido", "denunciante", "condenado", "acusado", "expediente",
    "resolución", "sentencia", "tribunal", "juzgado"
]

ANCHORS_CENSUS = [
    "nacionalidad", "edad", "salario", "profesión", "oficio", "estado civil",
    "soltero", "casado", "divorciado", "viudo", "ingresos", "domiciliado",
    "vecino de", "residente de", "ocupación", "género", "sexo"
]

# Roles públicos institucionales que NO se deben anonimizar (Whitelist de transparencia)
WHITELIST_ROLES = [
    "juez", "jueza", "magistrado", "magistrada", "fiscal", "notario", "notaria", 
    "registrador", "registradora", "defensor", "defensora", "alcalde", "alcaldesa", 
    "ministro", "ministra", "presidente", "presidenta", "diputado", "diputada"
]
