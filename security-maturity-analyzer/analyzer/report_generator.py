"""
Report Generator
Produces a rich console report (with ANSI colours) and an HTML report
that can be opened in any browser.
"""

import os
import json
import datetime
from typing import Optional
from pathlib import Path

from analyzer.maturity_scorer import MaturityResult, DomainScore
from rules.iso27001_controls import MATURITY_LEVELS

# ─────────────────────────────────────────────────────────
# Console report
# ─────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREY   = "\033[90m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"


def _bar(score: float, width: int = 40) -> str:
    filled = int(round(score / 100 * width))
    colour = GREEN if score >= 61 else (YELLOW if score >= 21 else RED)
    return colour + "█" * filled + GREY + "░" * (width - filled) + RESET


def _level_colour(level: int) -> str:
    return {0: RED, 1: RED, 2: YELLOW, 3: YELLOW, 4: GREEN, 5: GREEN}.get(level, WHITE)


def print_console_report(result: MaturityResult, log_path: str) -> None:
    width = 70
    sep  = GREY + "─" * width + RESET
    sep2 = GREY + "═" * width + RESET

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lvl = result.overall_level
    lvl_info = MATURITY_LEVELS[lvl]
    lvl_colour = _level_colour(lvl)

    print()
    print(sep2)
    print(BOLD + CYAN + "  MODELO DE EVALUACIÓN DE MADUREZ EN SEGURIDAD DE LA INFORMACIÓN" + RESET)
    print(GREY + f"  Basado en ISO/IEC 27001 | COBIT Maturity Model | {now}" + RESET)
    print(sep2)

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print(BOLD + WHITE + "  RESUMEN EJECUTIVO" + RESET)
    print(sep)
    print(f"  Archivo / Directorio analizado : {CYAN}{log_path}{RESET}")
    print(f"  Total de eventos procesados    : {WHITE}{result.total_events:,}{RESET}")
    print(f"  Eventos de riesgo detectados   : {RED}{result.total_risk_events:,}{RESET}")
    print(f"  Dominios con monitoreo activo  : {WHITE}{result.total_domains_active}{RESET} / {len(result.domain_scores)}")
    print()

    # ── Overall maturity ──────────────────────────────────────────────────
    print(BOLD + WHITE + "  NIVEL DE MADUREZ GLOBAL" + RESET)
    print(sep)
    print(f"  Score global : {BOLD}{lvl_colour}{result.overall_score:.1f} / 100{RESET}")
    print(f"  {_bar(result.overall_score)}")
    print()
    print(f"  Nivel {lvl} — {BOLD}{lvl_colour}{lvl_info['name']}{RESET}")
    print()
    # Wrap description to 65 chars
    desc_words = lvl_info["description"].split()
    line, lines = "  ", []
    for w in desc_words:
        if len(line) + len(w) + 1 > 67:
            lines.append(line)
            line = "  " + w + " "
        else:
            line += w + " "
    lines.append(line)
    print(GREY + "\n".join(lines) + RESET)

    # ── Visual level ladder ───────────────────────────────────────────────
    print()
    print(sep)
    for i in range(5, -1, -1):
        info  = MATURITY_LEVELS[i]
        lo, hi = info["range"]
        rng   = f"{lo:3d}–{hi:3d}%" if i > 0 else "  0%   "
        mark  = "◄ NIVEL ACTUAL" if i == lvl else ""
        col   = _level_colour(i)
        bold  = BOLD if i == lvl else ""
        print(f"  {bold}{col}Nivel {i}  {rng}  {info['name']:<28}{RESET}  {GREY}{mark}{RESET}")
    print(sep)

    # ── Per-domain scores ─────────────────────────────────────────────────
    print()
    print(BOLD + WHITE + "  EVALUACIÓN POR DOMINIO ISO 27001" + RESET)
    print(sep)

    for key, ds in sorted(result.domain_scores.items(),
                          key=lambda x: x[1].raw_score):
        col  = _level_colour(ds.level)
        print()
        print(f"  {BOLD}{col}{ds.domain_name}{RESET}  {GREY}({ds.clause}){RESET}")
        print(f"  Score : {col}{ds.raw_score:5.1f}/100{RESET}   "
              f"Nivel {ds.level} — {col}{ds.level_name}{RESET}   "
              f"{GREY}(peso {ds.weight:.0%}){RESET}")
        print(f"  {_bar(ds.raw_score, 38)}")
        # Breakdown
        bd = ds.breakdown
        print(
            f"  {GREY}Presencia:{bd.get('logging_presence',0):.1f}  "
            f"Efectividad:{bd.get('control_effectiveness',0):.1f}  "
            f"Severidad:{bd.get('severity_adjustment',0):+.1f}  "
            f"Cobertura:{bd.get('coverage_bonus',0):.1f}{RESET}"
        )
        if ds.notes:
            for note in ds.notes:
                print(f"  {YELLOW}⚠ {note}{RESET}")

    # ── Critical findings ─────────────────────────────────────────────────
    if result.critical_findings:
        print()
        print(sep)
        print(BOLD + RED + "  HALLAZGOS CRÍTICOS" + RESET)
        print(sep)
        for f in result.critical_findings:
            print(f"  {RED}✖ {f}{RESET}")

    # ── Recommendations ───────────────────────────────────────────────────
    print()
    print(sep)
    print(BOLD + WHITE + "  RECOMENDACIONES" + RESET)
    print(sep)
    for i, rec in enumerate(result.recommendations, 1):
        print(f"  {BLUE}{i:2d}.{RESET} {rec}")

    print()
    print(sep2)
    print(GREY + "  Ref: ISO/IEC 27001:2013 | COBIT 5 | NTP ISO/IEC 27001:2008" + RESET)
    print(sep2)
    print()


# ─────────────────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────────────────

def export_json(result: MaturityResult, output_path: str) -> None:
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "overall": {
            "score": result.overall_score,
            "level": result.overall_level,
            "level_name": result.overall_level_name,
            "total_events": result.total_events,
            "total_risk_events": result.total_risk_events,
        },
        "domains": {
            key: {
                "name": ds.domain_name,
                "clause": ds.clause,
                "weight": ds.weight,
                "score": ds.raw_score,
                "level": ds.level,
                "level_name": ds.level_name,
                "breakdown": ds.breakdown,
                "notes": ds.notes,
            }
            for key, ds in result.domain_scores.items()
        },
        "critical_findings": result.critical_findings,
        "recommendations": result.recommendations,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────

def export_html(result: MaturityResult, log_path: str, output_path: str) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lvl = result.overall_level
    lvl_info = MATURITY_LEVELS[lvl]

    def score_colour(s: float) -> str:
        if s >= 61: return "#4CAF50"
        if s >= 21: return "#FFC107"
        return "#F44336"

    def level_badge(l: int) -> str:
        info = MATURITY_LEVELS[l]
        c = score_colour(info["range"][1])
        return (f'<span style="background:{c};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-size:.85em;">Nivel {l} — {info["name"]}</span>')

    def progress_bar(score: float, width: str = "100%") -> str:
        c = score_colour(score)
        return (f'<div style="background:#2a2a2a;border-radius:4px;height:18px;'
                f'width:{width};overflow:hidden;">'
                f'<div style="width:{score:.1f}%;background:{c};height:100%;'
                f'border-radius:4px;transition:width .4s;"></div></div>')

    domain_rows = ""
    for key, ds in sorted(result.domain_scores.items(),
                          key=lambda x: x[1].raw_score):
        notes_html = "".join(
            f'<li style="color:#FFC107;">⚠ {n}</li>' for n in ds.notes
        ) if ds.notes else ""
        bd = ds.breakdown
        domain_rows += f"""
        <tr>
          <td><strong>{ds.domain_name}</strong><br>
              <small style="color:#888">{ds.clause}</small></td>
          <td style="text-align:center">{level_badge(ds.level)}</td>
          <td style="text-align:center;font-size:1.2em;font-weight:bold;
                     color:{score_colour(ds.raw_score)}">{ds.raw_score:.1f}</td>
          <td style="width:200px">{progress_bar(ds.raw_score)}</td>
          <td style="font-size:.8em;color:#aaa">
            Presencia: {bd.get('logging_presence',0):.1f}<br>
            Efectividad: {bd.get('control_effectiveness',0):.1f}<br>
            Severidad: {bd.get('severity_adjustment',0):+.1f}<br>
            Cobertura: {bd.get('coverage_bonus',0):.1f}
          </td>
          <td><ul style="margin:0;padding-left:16px">{notes_html}</ul></td>
        </tr>
        """

    findings_html = "".join(
        f'<li style="color:#F44336;margin-bottom:6px;">✖ {f}</li>'
        for f in result.critical_findings
    ) or "<li>Sin hallazgos críticos.</li>"

    recs_html = "".join(
        f'<li style="margin-bottom:8px;">{r}</li>'
        for r in result.recommendations
    )

    level_ladder = ""
    for i in range(5, -1, -1):
        info = MATURITY_LEVELS[i]
        lo, hi = info["range"]
        rng = f"{lo}–{hi}%"
        bg  = "#1e3a1e" if i == lvl else "#1a1a1a"
        bc  = score_colour(info["range"][1]) if i == lvl else "#333"
        fw  = "bold" if i == lvl else "normal"
        mark = "◄ NIVEL ACTUAL" if i == lvl else ""
        level_ladder += (
            f'<div style="display:flex;align-items:center;gap:16px;'
            f'padding:8px 12px;border-radius:6px;background:{bg};'
            f'border:1px solid {bc};margin-bottom:6px;font-weight:{fw};">'
            f'<span style="color:{score_colour(info["range"][1])};'
            f'min-width:70px;">Nivel {i}</span>'
            f'<span style="min-width:80px;color:#aaa">{rng}</span>'
            f'<span style="flex:1">{info["name"]}</span>'
            f'<span style="color:{score_colour(info["range"][1])};font-size:.85em">{mark}</span>'
            f'</div>'
        )

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evaluación de Madurez en Seguridad de la Información</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#111; color:#e0e0e0;
         margin:0; padding:24px; }}
  h1,h2,h3 {{ color:#90CAF9; }}
  h1 {{ font-size:1.5em; }}
  .card {{ background:#1e1e1e; border:1px solid #333; border-radius:8px;
           padding:20px; margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; font-size:.92em; }}
  th {{ background:#263238; color:#90CAF9; padding:10px 12px; text-align:left; }}
  td {{ padding:10px 12px; border-bottom:1px solid #2a2a2a; vertical-align:top; }}
  tr:hover td {{ background:#222; }}
  .big-score {{ font-size:3em; font-weight:bold; color:{score_colour(result.overall_score)}; }}
  .subtitle {{ color:#888; font-size:.88em; }}
  ul {{ list-style:disc; padding-left:18px; }}
  li {{ margin-bottom:4px; }}
  footer {{ color:#555; font-size:.8em; margin-top:30px; text-align:center; }}
</style>
</head>
<body>
<h1>🛡 Modelo de Evaluación de Madurez en Seguridad de la Información</h1>
<p class="subtitle">Basado en ISO/IEC 27001:2013 | COBIT Maturity Model | NTP ISO/IEC 27001:2008<br>
Generado: {now} | Fuente: {log_path}</p>

<div class="card">
  <h2>Resultado Global</h2>
  <div style="display:flex;align-items:center;gap:40px;flex-wrap:wrap;">
    <div style="text-align:center;">
      <div class="big-score">{result.overall_score:.1f}</div>
      <div style="color:#888">/ 100 puntos</div>
    </div>
    <div style="flex:1;min-width:220px;">
      {progress_bar(result.overall_score)}
      <div style="margin-top:12px">{level_badge(lvl)}</div>
      <p style="margin-top:12px;color:#bbb;font-size:.9em;">{lvl_info['description']}</p>
    </div>
    <div style="background:#1a2a1a;border-radius:8px;padding:14px;min-width:180px;">
      <div style="color:#888;font-size:.85em;">Estadísticas</div>
      <div>📋 Eventos: <strong>{result.total_events:,}</strong></div>
      <div>⚠ Riesgos: <strong style="color:#F44336">{result.total_risk_events:,}</strong></div>
      <div>✅ Dominios activos: <strong>{result.total_domains_active}</strong></div>
    </div>
  </div>
</div>

<div class="card">
  <h2>Escala de Madurez</h2>
  {level_ladder}
</div>

<div class="card">
  <h2>Evaluación por Dominio ISO 27001</h2>
  <table>
    <thead>
      <tr>
        <th>Dominio</th><th>Nivel</th><th>Score</th>
        <th>Barra</th><th>Desglose</th><th>Notas</th>
      </tr>
    </thead>
    <tbody>{domain_rows}</tbody>
  </table>
</div>

<div class="card">
  <h2 style="color:#F44336;">⚠ Hallazgos Críticos</h2>
  <ul>{findings_html}</ul>
</div>

<div class="card">
  <h2>📋 Recomendaciones</h2>
  <ol>{recs_html}</ol>
</div>

<footer>
  Referencia: ISO/IEC 27001:2013 · COBIT 5 · NTP ISO/IEC 27001:2008 · SMESEC Framework<br>
  Tesis: "Modelo de Evaluación de la Madurez en Seguridad de la Información"
</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
