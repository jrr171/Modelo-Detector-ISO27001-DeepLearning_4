#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Modelo de Evaluación de Madurez en Seguridad de la Información             ║
║  Usando Simulador para la Detección de Incumplimiento de Requisitos         ║
║                                                                              ║
║  Basado en:  ISO/IEC 27001:2013                                             ║
║              COBIT Maturity Model (Niveles 0–5)                             ║
║              NTP ISO/IEC 27001:2008 (Norma Técnica Peruana)                 ║
║              Framework SMESEC                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

Uso:
  python main.py <ruta_de_logs>               Analizar logs en ruta
  python main.py --demo                       Usar logs de muestra incluidos
  python main.py <ruta> --html informe.html   Generar reporte HTML
  python main.py <ruta> --json datos.json     Exportar resultados en JSON
  python main.py <ruta> --quiet              Solo mostrar nivel final
"""

import sys
import os
import argparse
import logging
import time
from pathlib import Path

# ── Path fix so sub-modules resolve ──────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from analyzer.log_parser    import LogParser
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer  import MaturityScorer
from analyzer.report_generator import (
    print_console_report,
    export_json,
    export_html,
)
from rules.iso27001_controls import MATURITY_LEVELS


# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Evaluador de Madurez en Seguridad de la Información",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "log_path",
        nargs="?",
        help="Ruta al archivo de log o directorio con logs.",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Ejecutar con los logs de muestra incluidos (directorio samples/).",
    )
    p.add_argument(
        "--html",
        metavar="FILE",
        help="Exportar reporte HTML a FILE.",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        help="Exportar resultados en formato JSON a FILE.",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Mostrar sólo el nivel de madurez final (sin detalles).",
    )
    p.add_argument(
        "--max-lines",
        type=int,
        default=500_000,
        metavar="N",
        help="Máximo de líneas a procesar por archivo (default: 500 000).",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mostrar logs de depuración.",
    )
    return p


def ensure_samples() -> str:
    """Generate sample logs if they don't exist yet."""
    samples_dir = Path(__file__).parent / "samples"
    sample_files = list(samples_dir.glob("sample_*.log")) + list(samples_dir.glob("sample_*.csv"))
    if not sample_files:
        print("Generando logs de muestra…")
        import subprocess
        subprocess.run(
            [sys.executable, str(samples_dir / "generate_samples.py")],
            check=True,
        )
    return str(samples_dir)


def main() -> int:
    args = build_parser().parse_args()

    # ── Logging setup ─────────────────────────────────────────────────────
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s | %(name)s | %(message)s",
    )

    # ── Resolve input path ────────────────────────────────────────────────
    if args.demo:
        log_path = ensure_samples()
    elif args.log_path:
        log_path = args.log_path
    else:
        build_parser().print_help()
        print("\nERROR: Debes indicar una ruta o usar --demo\n")
        return 1

    if not Path(log_path).exists():
        print(f"ERROR: La ruta '{log_path}' no existe.")
        return 1

    # ── Pipeline ──────────────────────────────────────────────────────────
    t0 = time.perf_counter()

    if not args.quiet:
        print(f"\n  Analizando: {log_path}")
        print("  ⏳ Leyendo y clasificando eventos…")

    # 1. Parse
    parser = LogParser(max_lines=args.max_lines)
    entries = parser.parse_path(log_path)

    if not entries:
        print("\n  ⚠  No se encontraron eventos legibles en la ruta indicada.")
        print("     Verifica que el archivo tenga formato Apache, syslog, CSV de Windows o JSON.\n")
        return 2

    if not args.quiet:
        ps = parser.stats
        print(
            f"  📋 {ps['files_processed']} archivo(s) | "
            f"{ps['total_lines']:,} líneas | "
            f"{ps['parsed_ok']:,} eventos válidos"
        )

    # 2. Classify
    classifier = EventClassifier()
    domain_stats = classifier.classify(entries)

    # 3. Score
    scorer = MaturityScorer()
    result = scorer.score(domain_stats)

    elapsed = time.perf_counter() - t0

    # ── Output ────────────────────────────────────────────────────────────
    if args.quiet:
        lvl  = result.overall_level
        name = MATURITY_LEVELS[lvl]["name"]
        print(f"Nivel de Madurez: {lvl} — {name} ({result.overall_score:.1f}/100)")
        return 0

    # Console report
    print_console_report(result, log_path)
    print(f"  ⏱  Análisis completado en {elapsed:.2f}s\n")

    # HTML export
    if args.html:
        export_html(result, log_path, args.html)
        print(f"  💾 Reporte HTML guardado en: {args.html}\n")

    # JSON export
    if args.json:
        export_json(result, args.json)
        print(f"  💾 Datos JSON guardados en:  {args.json}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
