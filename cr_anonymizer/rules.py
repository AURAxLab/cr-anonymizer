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

# Fechas (numéricas e híbridas con nombres de meses en español)
REGEX_DATE = re.compile(
    r'\b\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}\b|'
    r'\b\d{1,2}\s+de\s+(?:enero|febrero|marzo|abril|mayo|junio|julio|agosto|setiembre|septiembre|octubre|noviembre|diciembre)\s+(?:del?\s+)?\d{2,4}\b',
    re.IGNORECASE
)

# Expediente Judicial (formato del Poder Judicial: YY-NNNNNN-XXXX-JR)
REGEX_COURT_CASE = re.compile(r'\b\d{2}-\d{6}-\d{4}-[A-Z]{2,4}\b')

# Tarjetas de Crédito / Débito (15 o 16 dígitos separados por espacio o guion)
REGEX_CREDIT_CARD = re.compile(r'\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b')

# Edad
REGEX_AGE = re.compile(r'\b\d{1,3}\s*años\s*(?:de\s*edad)?\b|\bedad\s*(?:de|:)?\s*\d{1,3}\b', re.IGNORECASE)

# Montos de dinero (salarios, deudas, etc.)
REGEX_FINANCIAL_MONEY = re.compile(r'\b(?:[₡$]|USD|EUR)\s*\d+(?:[.,]\d+)*\b|\b\d+(?:[.,]\d+)*\s*(?:colones|dólares|euros)\b', re.IGNORECASE)


# --- Diccionarios de Anclas de Contexto y Listas Blancas ---

ANCHORS_HEALTH = [
    "diagnóstico", "sintomatología", "padece", "padece de", "sufre de",
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

# --- NUEVOS DICCIONARIOS Y ANCLAS ---

# Base de datos de enfermedades comunes (Detección directa)
HEALTH_DISEASES_DB = {
    "tuberculosis", "cáncer", "cancer", "diabetes", "asma", "vih", "sida", 
    "leucemia", "hipertensión", "hipertension", "depresión", "depresion", 
    "esquizofrenia", "esclerosis", "neumonía", "neumonia", "infarto", 
    "demencia", "alzheimer", "epilepsia", "insuficiencia renal", "covid"
}

# Base de datos de medicamentos comunes
HEALTH_MEDICINES_DB = {
    "acetaminofén", "acetaminofen", "ibuprofeno", "amoxicilina", "insulina", 
    "metformina", "clonazepam", "diazepam", "salbutamol", "loratadina", 
    "enalapril", "omeprazol", "paracetamol", "penicilina", "aspirina"
}

# Lista blanca de instituciones públicas en Costa Rica (Transparencia)
WHITELIST_PUBLIC_ENTITIES = {
    "caja costarricense de seguro social", "ccss", "poder judicial", 
    "ministerio de hacienda", "ministerio de educación pública", "mep", 
    "instituto costarricense de electricidad", "ice", "instituto nacional de seguros", "ins", 
    "patronato nacional de la infancia", "pani", "tribunal supremo de elecciones", "tse", 
    "organismo de investigación judicial", "oij", "municipalidad de san josé", "municipalidad de san jose"
}

# Creencias y afiliaciones políticas/sindicales
BELIEFS_RELIGIONS = {
    "católico", "católica", "catolico", "catolica", "evangélico", "evangélica", 
    "evangelico", "evangelica", "mormón", "mormon", "testigo de jehová", 
    "testigo de jehova", "judío", "judía", "judio", "judia", "musulmán", 
    "musulman", "protestante"
}

BELIEFS_POLITICAL_UNIONS = {
    "pln", "pusc", "pac", "frente amplio", "sindicato", "apse", "ande", "sec"
}

# Anclas para clasificar fechas de nacimiento
ANCHORS_BIRTH = {
    "nacimiento", "nacer", "nacido", "nacida", "natalicio", "fec_nac"
}

# Anclas de inicio de dirección
ANCHORS_ADDRESS = {
    "vecino", "domiciliado", "dirección", "direccion", "señas", "senas", "residente"
}

# Elementos direccionales costarricenses
ANCHORS_DIRECTIONAL = {
    "norte", "sur", "este", "oeste", "noreste", "sureste", "noroeste", "suroeste", 
    "arriba", "abajo", "mano derecha", "mano izquierda"
}

# Elementos métricos de distancia costarricenses
ANCHORS_METRIC = {
    "metros", "mts", "varas", "cuadras", "km", "kilómetros", "kilometros"
}

# Hitos y referencias geográficas locales costarricenses
ANCHORS_LANDMARK = {
    "frente", "detrás", "detras", "esquina", "casa", "portón", "porton", "tapia", 
    "edificio", "iglesia", "escuela", "pulpería", "pulperia", "supermercado", "del", "al"
}

# Palabras clave de SINPE Móvil
KEYWORDS_SINPE = {
    "sinpe", "sinpe móvil", "sinpe movil", "pago móvil", "pago movil"
}
