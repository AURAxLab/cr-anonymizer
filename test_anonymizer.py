import json
from cr_anonymizer import CRDetector, CRAnonymizer, SensitivityLevel

def run_tests():
    print("==================================================")
    print(" INICIALIZANDO DETECTOR INTELIGENTE DE PII DE CR ")
    print("==================================================")
    
    # We use 'sm' model for test speed
    detector = CRDetector(model_size="sm")
    
    # --- CASO DE PRUEBA 1: EXPEDIENTE MÉDICO (Sanatorio Durán) ---
    print("\n\n>>> CASO DE PRUEBA 1: Expediente Histórico del Sanatorio Durán")
    medical_text = (
        "Expediente Clínico N.º 2309-SD. El paciente Carlos Alvarado Gómez, vecino de Cartago, "
        "con cédula física 1-0899-0234, ingresó presenting una sintomatología severa. "
        "Tras los análisis clínicos y radiológicos, el Dr. Rafael Ángel Calderón Guardia confirma "
        "un diagnóstico de Tuberculosis pulmonar activa y ordena tratamiento inmediato. "
        "El paciente declara tener un salario de ₡350000 mensuales y no cuenta con seguro social."
    )
    print("Texto Original:\n", medical_text)
    
    findings = detector.analyze(medical_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings], indent=2, ensure_ascii=False))
    
    redacted_med = CRAnonymizer.anonymize(medical_text, findings, redact_levels=[
        SensitivityLevel.SENSIBLE, 
        SensitivityLevel.RESTRINGIDO
    ])
    print("\nTexto Anonimizado (SENSIBLE + RESTRINGIDO):\n", redacted_med)
    
    
    # --- CASO DE PRUEBA 2: ESCRITURA LEGAL (Notaría) ---
    print("\n\n>>> CASO DE PRUEBA 2: Escritura Pública de Compraventa")
    legal_text = (
        "ANTE MÍ, la Notaria Pública María Elena Chinchilla, comparece el señor Juan Carlos Pérez Brenes, "
        "mayor de edad, casado una vez, portador de la cédula de identidad número 2-0345-0987, vecino de Alajuela, "
        "quien transfiere la propiedad inscrita en el Registro Nacional bajo matrícula Folio Real número 12345-000 "
        "a la sociedad Corporación Textil S.A., con cédula jurídica 3-101-456789. "
        "El precio de venta se pacta en la suma de $50000 pagados mediante transferencia al IBAN CR10015201001010101010."
    )
    print("Texto Original:\n", legal_text)
    
    findings_legal = detector.analyze(legal_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_legal], indent=2, ensure_ascii=False))
    
    redacted_legal = CRAnonymizer.anonymize(legal_text, findings_legal, redact_levels=[
        SensitivityLevel.SENSIBLE, 
        SensitivityLevel.RESTRINGIDO,
        SensitivityLevel.IRRESTRICTO
    ])
    print("\nTexto Anonimizado Completo (Todos los niveles):\n", redacted_legal)
    
    
    # --- CASO DE PRUEBA 3: ARTÍCULO DE PERIÓDICO (Prensa Pública) ---
    print("\n\n>>> CASO DE PRUEBA 3: Artículo de Prensa sobre Asuntos Públicos")
    news_text = (
        "El Tribunal Supremo de Elecciones anunció la reelección en la alcaldía. "
        "El Alcalde Roberto Thompson Chacón defendió el plan de ordenamiento vial de la provincia. "
        "Al evento asistieron los vecinos de San José y representantes de varias cooperativas locales. "
        "Cualquier consulta al correo municipalidad@sanjose.go.cr o al teléfono 2222-3333."
    )
    print("Texto Original:\n", news_text)
    
    findings_news = detector.analyze(news_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_news], indent=2, ensure_ascii=False))
    
    redacted_news = CRAnonymizer.anonymize(news_text, findings_news, redact_levels=[
        SensitivityLevel.RESTRINGIDO
    ])
    print("\nTexto Anonimizado (Solo RESTRINGIDO - Mantiene Funcionario Público):\n", redacted_news)
 

    # --- CASO DE PRUEBA 4: EXPEDIENTE JUDICIAL (Caso Penal de Tránsito / Querella) ---
    print("\n\n>>> CASO DE PRUEBA 4: Expediente Judicial Penal")
    judicial_text = (
        "En el Tribunal Penal de Goicoechea, se tramita la querella contra el imputado Juan Manuel Santos, "
        "con cédula de identidad 1-1234-5678, por el presunto delito de colisión y lesiones. "
        "La víctima, la señora Ana Lorena Ruiz, declaró ante la Jueza instructora Dra. Patricia Vargas "
        "y el fiscal penal Lic. Rodrigo Arias Brenes, señalando que el imputado huyó del lugar."
    )
    print("Texto Original:\n", judicial_text)
    
    findings_judicial = detector.analyze(judicial_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_judicial], indent=2, ensure_ascii=False))
    
    redacted_judicial = CRAnonymizer.anonymize(judicial_text, findings_judicial, redact_levels=[
        SensitivityLevel.SENSIBLE,
        SensitivityLevel.RESTRINGIDO,
        SensitivityLevel.IRRESTRICTO
    ])
    print("\nTexto Anonimizado Completo (Expediente Judicial):\n", redacted_judicial)


    # --- CASO DE PRUEBA 5: EDGES CASES DE IDENTIFICACIONES (Múltiples formatos de IDs) ---
    print("\n\n>>> CASO DE PRUEBA 5: Formatos y Variaciones de Cédulas y DIMEX")
    formats_text = (
        "Para el registro de deudores, se verificaron los siguientes documentos de Costa Rica: "
        "Cédula física con espacios 1 0987 0123, cédula física con guiones 5-0234-0567, "
        "cédula física sin separación 203450987 y un DIMEX extranjero 155820102941."
    )
    print("Texto Original:\n", formats_text)
    
    findings_formats = detector.analyze(formats_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_formats], indent=2, ensure_ascii=False))
    
    redacted_formats = CRAnonymizer.anonymize(formats_text, findings_formats, redact_levels=[
        SensitivityLevel.RESTRINGIDO
    ])
    print("\nTexto Anonimizado (Solo Cédulas/DIMEX):\n", redacted_formats)


    # --- CASO DE PRUEBA 6: CARACTERÍSTICAS AVANZADAS (Fechas, DoB, Edad, Direcciones Descriptivas) ---
    print("\n\n>>> CASO DE PRUEBA 6: Fechas de Nacimiento, Edades y Direcciones Descriptivas ('Señas')")
    advanced_text = (
        "El señor Carlos nació el 12 de octubre de 1980 en San José y tiene 45 años de edad. "
        "El informe correspondiente se firmó el 5 de mayo del 2012. "
        "Su dirección física registrada es: Heredia, del parque 200 metros norte y 50 metros este, "
        "casa de portón negro, mano derecha."
    )
    print("Texto Original:\n", advanced_text)
    
    findings_adv = detector.analyze(advanced_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_adv], indent=2, ensure_ascii=False))
    
    redacted_adv = CRAnonymizer.anonymize(advanced_text, findings_adv, redact_levels=[
        SensitivityLevel.RESTRINGIDO,
        SensitivityLevel.SENSIBLE
    ])
    print("\nTexto Anonimizado (Restringido + Sensible):\n", redacted_adv)


    # --- CASO DE PRUEBA 7: SALUD AMPLIADA (Enfermedades y Medicamentos Comunes en CR) ---
    print("\n\n>>> CASO DE PRUEBA 7: Diagnósticos y Tratamientos Médicos (Salud)")
    health_text = (
        "El paciente padece de diabetes tipo 2 y se le recetó metformina diaria. "
        "En su expediente se detalla un diagnóstico previo de cáncer y neumonía. "
        "Además, toma acetaminofén para controlar los síntomas de dolores generales."
    )
    print("Texto Original:\n", health_text)
    
    findings_health = detector.analyze(health_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_health], indent=2, ensure_ascii=False))
    
    redacted_health = CRAnonymizer.anonymize(health_text, findings_health, redact_levels=[
        SensitivityLevel.SENSIBLE
    ])
    print("\nTexto Anonimizado (Solo SENSIBLE):\n", redacted_health)


    # --- CASO DE PRUEBA 8: FINANZAS Y SINPE MÓVIL (Luhn Check, SINPE y Salarios) ---
    print("\n\n>>> CASO DE PRUEBA 8: Tarjetas de Crédito (Luhn), SINPE y Salario")
    finance_text = (
        "El cliente tiene un salario de ₡850000 mensuales. "
        "Realizó un pago por SINPE al número 8888-8888 de la cuenta corriente. "
        "Se registraron dos tarjetas para cobro: una Visa válida 4000-1234-5678-9017 y "
        "una tarjeta inválida 1234-5678-9012-3456."
    )
    print("Texto Original:\n", finance_text)
    
    findings_finance = detector.analyze(finance_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_finance], indent=2, ensure_ascii=False))
    
    redacted_finance = CRAnonymizer.anonymize(finance_text, findings_finance, redact_levels=[
        SensitivityLevel.SENSIBLE,
        SensitivityLevel.RESTRINGIDO
    ])
    print("\nTexto Anonimizado (Sensible + Restringido):\n", redacted_finance)


    # --- CASO DE PRUEBA 9: CAUSAS JUDICIALES, CREENCIAS Y TRANSPARENCIA PÚBLICA ---
    print("\n\n>>> CASO DE PRUEBA 9: Expediente Judicial Penal, Creencias y Lista Blanca")
    judicial_adv_text = (
        "Bajo el expediente de causa judicial número 20-000123-0042-PE del Poder Judicial, "
        "se procesa al imputado Rodrigo Chaves por presunto delito contra la hacienda. "
        "El expediente fue enviado a la Caja Costarricense de Seguro Social (CCSS) "
        "por orden del Magistrado y el Notario Público. "
        "El señor declaró en la comparecencia ser de convicción católico y miembro del sindicato APSE."
    )
    print("Texto Original:\n", judicial_adv_text)
    
    findings_jud_adv = detector.analyze(judicial_adv_text)
    print("\nResultados de Detección (JSON):")
    print(json.dumps([f.to_json() for f in findings_jud_adv], indent=2, ensure_ascii=False))
    
    redacted_jud_adv = CRAnonymizer.anonymize(judicial_adv_text, findings_jud_adv, redact_levels=[
        SensitivityLevel.SENSIBLE,
        SensitivityLevel.RESTRINGIDO,
        SensitivityLevel.IRRESTRICTO
    ])
    print("\nTexto Anonimizado Completo:\n", redacted_jud_adv)

if __name__ == "__main__":
    run_tests()
