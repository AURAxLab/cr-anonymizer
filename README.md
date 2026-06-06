# cr-anonymizer 🇨🇷

Un módulo genérico y reutilizable en Python para la **detección y catalogación inteligente** de datos personales (PII) y sensibles bajo la legislación de Costa Rica, específicamente alineado con la **Ley de Protección de la Persona frente al Tratamiento de sus Datos Personales (Ley N.º 8968)**.

---

## 📋 Descripción General

`cr-anonymizer` ha sido diseñado bajo un principio estricto de **separación de responsabilidades**:
1. **Detección Pura (`CRDetector`):** Escanea cualquier texto plano y retorna las coordenadas exactas de caracteres (`start_char`, `end_char`), el valor original, el tipo de dato y su clasificación legal de sensibilidad. **No altera el texto original**.
2. **Procesador Auxiliar (`CRAnonymizer`):** Proporciona un mecanismo de enmascaramiento consistente determinista (ej. `[PERSONA_1]` siempre representará al mismo individuo en todo el documento) procesando las entidades de derecha a izquierda para evitar el desplazamiento de índices de caracteres.

Esta arquitectura desacoplada permite que otros sistemas tomen las decisiones de negocio sobre si conservar ciertos datos por valor histórico o anonimizarlos.

---

## ⚖️ Clasificación según la Ley N.º 8968

El motor clasifica cada hallazgo automáticamente en uno de los niveles de intimidad estipulados por el **Artículo 3** de la legislación costarricense:

### 🔴 Sensibles (`SENSIBLE`)
Datos del fuero más íntimo del habitante cuyo tratamiento está prohibido excepto por consentimiento escrito expreso:
* **Datos de Salud (`HEALTH_DATA`):** Diagnósticos clínicos, patologías (ej. tuberculosis, asma), tratamientos o recetas.
* **Condición Financiera (`FINANCIAL_STATUS`):** Salarios detallados, ingresos o deudas privadas.

### 🟡 Restringidos (`RESTRINGIDO`)
Datos de interés exclusivo para el titular y la Administración Pública, cuyo tratamiento comercial requiere consentimiento:
* **Identificación Nacional (`ID_PHYSICAL`, `ID_MIGRATORY`):** Cédula de identidad física costarricense o DIMEX (extranjería).
* **Contacto Privado (`PHONE`, `EMAIL`, `IP_ADDRESS`):** Teléfonos, correos electrónicos o direcciones IP.
* **Localización Física (`LOCATION`):** Domicilio o vecindario exacto de residencia de particulares.

### 🟢 Irrestrictos (`IRRESTRICTO`)
Datos contenidos en registros públicos de libre acceso general:
* **Nombres de Particulares (`NAME`):** Nombres y apellidos.
* **Estado Civil (`MARITAL_STATUS`):** Casado, soltero, divorciado, viudo.
* **Cédulas Jurídicas (`ID_JURIDICAL`):** Identificaciones de empresas/sociedades.
* **Cargos Públicos Whitelist (`PUBLIC_OFFICIAL`):** Nombres de funcionarios públicos (jueces, alcaldes, notarios) que por transparencia estatal no deben anonimizarse.

---

## 🛠️ Arquitectura del Motor de Detección

El motor `CRDetector` utiliza un enfoque de **reglas híbridas multidominio**:

1. **Expresiones Regulares Locales:** Identificación determinista de cédulas físicas (formatos `1-1111-1111`, `1 1111 1111`, `111111111`), DIMEX (11-12 dígitos), cédulas jurídicas (`3-101-XXXXXX`), cuentas IBAN nacionales (`CR...`), números telefónicos costarricenses y correos electrónicos.
2. **Procesamiento de Lenguaje Natural (NLP):** Integración con **SpaCy** en español para extraer nombres propios (`PER`) y localizaciones (`LOC`).
3. **Capa de Corrección y Reclasificación Gramatical:** Corrige falsas etiquetas del NLP mediante reglas avanzadas del español (ej. reclasifica entidades etiquetadas como `LOC` o `MISC` a `PUBLIC_OFFICIAL` o `NAME` cuando están precedidas por cargos o títulos de cortesía como *Notaria*, *Alcalde*, *Dr.*, *Dra.*).
4. **Inferencia Contextual Basada en Tokens:** Utiliza las dependencias gramaticales y etiquetas POS (Part-of-Speech) de SpaCy para escanear ventanas de texto tras palabras ancla (ej. *"diagnóstico de"*, *"salario de"*) y acumula secuencias de sustantivos, adjetivos y números, filtrando verbos auxiliares y stop words comunes.
5. **Resolución de Traslapes:** Consolida y elimina colisiones de coordenadas de caracteres, priorizando las entidades más específicas y de mayor confianza.

---

## 🚀 Instalación y Uso

### Requisitos Previos
* Python 3.8 o superior
* SpaCy y su modelo en español

```bash
pip install spacy click
python -m spacy download es_core_news_sm
```

### Ejecutar Pruebas
El proyecto incluye un set de pruebas en `test_anonymizer.py` con tres escenarios (expediente médico, escritura notarial de compraventa y artículo de prensa pública):

```bash
python test_anonymizer.py
```

### Ejemplo de Código

```python
from cr_anonymizer import CRDetector, CRAnonymizer, SensitivityLevel

# 1. Inicializar el detector (descarga automáticamente el modelo si no existe)
detector = CRDetector(model_size="sm")

# 2. Analizar el texto
texto = "El paciente Carlos Alvarado Gómez presenta Tuberculosis pulmonar activa."
findings = detector.analyze(texto)

# 3. Inspeccionar hallazgos catalogados
for f in findings:
    print(f"{f.entity_type} ({f.sensitivity_level}): {f.value} [{f.start_char}-{f.end_char}]")

# 4. Anonimizar niveles específicos (Sensible y Restringido por defecto)
texto_anonimo = CRAnonymizer.anonymize(texto, findings, redact_levels=[
    SensitivityLevel.SENSIBLE, 
    SensitivityLevel.RESTRINGIDO
])
print(texto_anonimo)
# El paciente Carlos Alvarado Gómez presenta [HEALTH_DATA].
```

---

## 📂 Estructura del Repositorio

* `cr_anonymizer/`
  * `__init__.py`: Punto de entrada del módulo.
  * `detector.py`: Lógica del motor de análisis híbrido.
  * `rules.py`: Regexes nacionales costarricenses y diccionarios de anclas.
  * `anonymizer.py`: Helper para enmascaramiento inverso consistente.
* `test_anonymizer.py`: Suite de validación de escenarios de Costa Rica.
* `README.md`: Este archivo explicativo.

---

## ✍️ Autor y Licencia

Este proyecto es propiedad y desarrollado por **Alexander Barquero**. Distribuido bajo la licencia **MIT** (consulte el archivo `LICENSE` para más información).

