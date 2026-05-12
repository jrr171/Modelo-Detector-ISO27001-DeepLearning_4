# 🛡 Modelo de Evaluación de Madurez en Seguridad de la Información

> **Tesis:** *Modelo de Evaluación De la Madurez en Seguridad de la Información Usando Simulador para la Detección de Incumplimiento de Requisitos en una Empresa de Inteligencia Comercial en el Sector Comercio Exterior*

Herramienta de línea de comandos en Python puro que **lee logs de servidores reales** y determina automáticamente el **nivel de madurez en seguridad de la información** (0 al 5) según los estándares ISO/IEC 27001:2013, el modelo COBIT y la norma técnica peruana NTP ISO/IEC 27001:2008.

---

## 📐 Modelo de Madurez

Basado en el modelo COBIT adoptado por ISO 27001, con 6 niveles:

| Nivel | Nombre | Rango | Descripción |
|-------|--------|-------|-------------|
| **0** | Inexistente | 0 % | Sin controles. Alto riesgo. |
| **1** | Inicial / Ad Hoc | 1–20 % | Controles ad hoc, sin documentación ni supervisión. |
| **2** | Repetible pero Intuitivo | 21–40 % | Controles existen pero dependen de individuos. |
| **3** | Proceso Definido | 41–60 % | Controles documentados, evaluación periódica. |
| **4** | Administrado y Medible | 61–80 % | Ambiente efectivo, controles automatizados. |
| **5** | Optimizado | 81–100 % | Mejora continua, gestión proactiva de riesgos. |

### Dominios ISO 27001 evaluados

| Dominio | Cláusula | Peso |
|---------|----------|------|
| Control de Accesos | A.9 | 25 % |
| Seguridad en Operaciones | A.12 | 20 % |
| Seguridad en Comunicaciones | A.13 | 20 % |
| Gestión de Incidentes | A.16 | 15 % |
| Criptografía | A.10 | 10 % |
| Seguridad Física | A.11 | 10 % |

### Fórmula de puntuación

Cada dominio recibe un score de 0–100 construido a partir de 4 componentes:

```
Score_dominio = Presencia_logs + Efectividad_controles + Ajuste_severidad + Cobertura
```

| Componente | Máx. | Descripción |
|------------|------|-------------|
| Presencia de logs | 30 | Escala logarítmica según volumen de eventos |
| Efectividad de controles | 40 | Inversa de la tasa de eventos de riesgo |
| Ajuste por severidad | ±15 | Penalización por eventos CRITICAL/ERROR |
| Cobertura | 15 | IPs y usuarios únicos monitoreados |

```
Score_global = Σ (Score_dominio × Peso_dominio)
Nivel_madurez = f(Score_global)
```

---

## 📁 Estructura del proyecto

```
security-maturity-analyzer/
│
├── main.py                        # Punto de entrada CLI
│
├── analyzer/
│   ├── log_parser.py              # Parseo de logs (Apache, syslog, Windows CSV, JSON)
│   ├── event_classifier.py        # Clasificación por dominio ISO 27001
│   ├── maturity_scorer.py         # Cálculo de scores y nivel de madurez
│   └── report_generator.py        # Reportes consola + HTML + JSON
│
├── rules/
│   └── iso27001_controls.py       # Definiciones de controles y niveles COBIT
│
├── samples/
│   ├── generate_samples.py        # Genera logs de muestra realistas
│   ├── sample_apache.log          # Apache/Nginx access log
│   ├── sample_auth.log            # Linux auth.log / SSH
│   ├── sample_syslog.log          # Syslog del sistema
│   └── sample_windows_events.csv  # Windows Event Log (CSV)
│
├── tests/
│   └── test_analyzer.py           # 25+ pruebas unitarias e integración
│
├── output/                        # Reportes generados (excluido de git)
├── requirements.txt
└── README.md
```

---

## 🚀 Instalación y uso

### Requisitos

- Python 3.8 o superior
- Sin dependencias externas (solo librería estándar)

### Instalación

```bash
git clone https://github.com/TU_USUARIO/security-maturity-analyzer.git
cd security-maturity-analyzer
```

### Uso básico

```bash
# Demo con logs de muestra incluidos
python main.py --demo

# Analizar un archivo de log específico
python main.py /var/log/auth.log

# Analizar todos los logs de un directorio
python main.py /var/log/

# Generar reporte HTML (abrir en navegador)
python main.py /var/log/auth.log --html output/reporte.html

# Exportar datos en JSON
python main.py /var/log/ --json output/resultado.json

# Solo mostrar el nivel (útil para scripts)
python main.py /var/log/auth.log --quiet

# Ver todas las opciones
python main.py --help
```

### Ejemplo de salida

```
══════════════════════════════════════════════════════════════════════
  MODELO DE EVALUACIÓN DE MADUREZ EN SEGURIDAD DE LA INFORMACIÓN
  Basado en ISO/IEC 27001 | COBIT Maturity Model | 2024-01-15 10:30:00
══════════════════════════════════════════════════════════════════════

  RESUMEN EJECUTIVO
  ──────────────────────────────────────────────────────────────────
  Archivo analizado            : /var/log/
  Total de eventos procesados  : 1,800
  Eventos de riesgo detectados : 412
  Dominios con monitoreo activo: 4 / 6

  NIVEL DE MADUREZ GLOBAL
  ──────────────────────────────────────────────────────────────────
  Score global : 38.4 / 100
  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░

  Nivel 2 — Repetible pero Intuitivo

  EVALUACIÓN POR DOMINIO ISO 27001
  ──────────────────────────────────────────────────────────────────

  Control de Accesos  (A.9 – Access Control)
  Score : 42.1/100   Nivel 3 — Proceso Definido   (peso 25%)
  ████████████████████░░░░░░░░░░░░░░░░░░
  ⚠ Tasa de riesgo alta (18%). Controles insuficientes.

  [...]
```

---

## 📊 Formatos de log soportados

| Formato | Extensión | Ejemplo |
|---------|-----------|---------|
| Apache / Nginx Combined | `.log` | `192.168.1.1 - alice [01/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1234` |
| Linux syslog / auth.log | `.log` | `Jan  1 10:00:00 host sshd[123]: Accepted password for alice` |
| Syslog ISO 8601 | `.log` | `2024-01-01T10:00:00+00:00 host sshd[123]: ...` |
| Windows Event Log | `.csv` | CSV exportado desde Event Viewer o `wevtutil` |
| JSON estructurado | `.json` | `{"timestamp":"...","level":"ERROR","message":"..."}` |
| Gzip comprimido | `.gz` | Cualquier formato anterior comprimido |

El analizador **detecta automáticamente** el formato de cada archivo.

---

## 🧪 Ejecutar pruebas

```bash
# Instalar pytest
pip install pytest pytest-cov

# Ejecutar todas las pruebas
python -m pytest tests/ -v

# Con cobertura
python -m pytest tests/ --cov=analyzer --cov=rules --cov-report=term-missing
```

---

## 🔧 Generar logs de muestra

```bash
python samples/generate_samples.py
```

Genera 4 archivos de muestra con ~1 800 eventos realistas que incluyen
intentos de login, ataques de fuerza bruta, errores de sistema, bloqueos
de firewall, y más.

---

## 📖 Marco teórico

Este proyecto implementa el modelo de madurez descrito en:

- **ISO/IEC 27001:2013** — Sistema de Gestión de la Seguridad de la Información
- **COBIT 5** — Control Objectives for Information and Related Technology
- **NTP ISO/IEC 27001:2008** — Norma Técnica Peruana
- **Framework SMESEC** — Seguridad para PYMES peruanas (UPC, 2015)

### Los 6 niveles de madurez COBIT

El modelo evalúa el grado de madurez de cada control de seguridad comparando
la evidencia encontrada en los logs contra los criterios de cada nivel:

- **Nivel 0 – Inexistente:** No hay registros ni controles detectables.
- **Nivel 1 – Inicial:** Hay actividad pero sin documentación ni proceso formal.
- **Nivel 2 – Repetible:** Los controles existen pero dependen de personas clave.
- **Nivel 3 – Definido:** Los procesos están documentados y son predecibles.
- **Nivel 4 – Administrado:** Los controles están automatizados y se miden.
- **Nivel 5 – Optimizado:** Mejora continua integrada en la organización.

---

## 🤝 Contribuir

1. Fork del repositorio
2. Crear una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -m "Agregar soporte para formato X"`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Pull Request

---

## 📄 Licencia

MIT License — ver archivo `LICENSE` para detalles.

---

*Desarrollado como parte de la tesis "Modelo de Evaluación De la Madurez en Seguridad de la Información Usando Simulador para la Detección de Incumplimiento de Requisitos en una Empresa de Inteligencia Comercial en el Sector Comercio Exterior".*
