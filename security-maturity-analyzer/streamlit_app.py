"""
Streamlit Web App — Evaluador de Madurez en Seguridad de la Información
Tesis: Modelo de Evaluación De la Madurez en Seguridad de la Información
Usando Simulador para la Detección de Incumplimiento de Requisitos
en una Empresa de Inteligencia Comercial en el Sector Comercio Exterior

Gráficos incluidos:
  1. Medidor (gauge) de madurez global
  2. Radar de dominios ISO 27001
  3. Barras comparativas: riesgo vs seguro por dominio
  4. Desglose de componentes de score (stacked bar)
  5. Distribución de eventos por dominio (pie)
  6. Mapa de calor de tasa de riesgo por dominio
  7. Escala de madurez tipo semáforo (progress)
  8. Sunburst de eventos clasificados
  9. Histograma de niveles por dominio
"""

import sys, io, json, tempfile, os, math
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from analyzer.log_parser       import LogParser
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer  import MaturityScorer
from analyzer.report_generator import export_html, export_json
from rules.iso27001_controls   import MATURITY_LEVELS, ISO27001_DOMAINS

# ────────────────────────────────────────────────────────────────────────────
# Paleta de colores corporativa (tesis)
# ────────────────────────────────────────────────────────────────────────────
C = {
    "primary":   "#1565C0",
    "secondary": "#0D47A1",
    "success":   "#2E7D32",
    "warning":   "#F57F17",
    "danger":    "#C62828",
    "level": {
        0: "#B71C1C", 1: "#D32F2F", 2: "#F57C00",
        3: "#FBC02D", 4: "#388E3C", 5: "#1B5E20",
    },
    "domains": [
        "#1565C0","#6A1B9A","#00695C","#E65100","#4527A0","#00838F",
    ],
}

def level_color(lvl): return C["level"].get(lvl, "#555")

def score_color(s):
    if s >= 81: return C["level"][5]
    if s >= 61: return C["level"][4]
    if s >= 41: return C["level"][3]
    if s >= 21: return C["level"][2]
    if s >  0:  return C["level"][1]
    return C["level"][0]

def hex_rgba(hex_color: str, alpha: float = 1.0) -> str:
    """Convert #RRGGBB to rgba(r,g,b,alpha) for Plotly compatibility."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"rgba({r},{g},{b},{alpha})"


# ────────────────────────────────────────────────────────────────────────────
# Page config
# ────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Evaluador de Madurez ISO 27001 | Comercio Exterior",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  .main-title  { font-size:2.1rem; font-weight:800; color:#0D47A1; letter-spacing:-0.5px; }
  .subtitle    { font-size:.95rem; color:#546E7A; margin-bottom:1rem; }
  .section-hdr { font-size:1.2rem; font-weight:700; color:#1565C0;
                 border-left:4px solid #1565C0; padding-left:10px; margin:24px 0 12px; }
  .kpi-card    { background:#F8FAFF; border:1px solid #BBDEFB; border-radius:12px;
                 padding:16px 20px; text-align:center; }
  .kpi-val     { font-size:2rem; font-weight:800; }
  .kpi-lbl     { font-size:.8rem; color:#78909C; font-weight:600; letter-spacing:.5px; }
  .finding     { background:#FFF3E0; border-left:4px solid #FF6F00;
                 border-radius:6px; padding:8px 14px; margin-bottom:6px; font-size:.9rem; }
  .rec         { background:#E8F5E9; border-left:4px solid #388E3C;
                 border-radius:6px; padding:8px 14px; margin-bottom:6px; font-size:.9rem; }
  .chart-box   { background:#fff; border:1px solid #E3EAF5; border-radius:12px; padding:16px; }
  footer       { text-align:center; color:#90A4AE; font-size:.78rem; margin-top:40px; }
</style>
""", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# Sidebar
# ────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡 ISO 27001 Maturity")
    st.markdown("**Modelo COBIT — 6 Niveles**")
    for i in range(6):
        info = MATURITY_LEVELS[i]
        lo, hi = info["range"]
        rng = f"{lo}–{hi}%" if i > 0 else "0%"
        st.markdown(
            f"<div style='padding:5px 8px;margin-bottom:4px;border-radius:6px;"
            f"background:{level_color(i)}22;border-left:3px solid {level_color(i)};'>"
            f"<b style='color:{level_color(i)}'>Nivel {i}</b> · {rng}<br>"
            f"<span style='font-size:.8em;color:#555'>{info['name']}</span></div>",
            unsafe_allow_html=True,
        )
    st.divider()
    st.caption("ISO/IEC 27001:2013 · COBIT 5 · NTP ISO/IEC 27001:2008")
    st.caption("Comercio Exterior — Tesis 2025")

# ────────────────────────────────────────────────────────────────────────────
# Header
# ────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="main-title">🛡 Evaluador de Madurez en Seguridad de la Información</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Detección de Incumplimiento de Requisitos ISO 27001 mediante análisis de logs · Empresa de Inteligencia Comercial · Sector Comercio Exterior</div>', unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# Input tabs
# ────────────────────────────────────────────────────────────────────────────
tab_up, tab_demo, tab_paste = st.tabs(["📁 Subir archivos", "🧪 Demo Comercio Exterior", "📋 Pegar texto"])

entries, source_label = [], ""

with tab_up:
    st.markdown("**Formatos soportados:** Apache/Nginx `.log`, Linux syslog/auth.log, Windows Event Log `.csv`, JSON `.json`, `.gz`")
    uploaded = st.file_uploader("Arrastra tus archivos de log aquí", type=["log","txt","csv","json","gz"], accept_multiple_files=True)
    if uploaded:
        with tempfile.TemporaryDirectory() as d:
            for f in uploaded:
                (Path(d) / f.name).write_bytes(f.read())
            parser = LogParser()
            entries = parser.parse_path(d)
            source_label = f"{len(uploaded)} archivo(s)"
            st.success(f"✅ {parser.stats['parsed_ok']:,} eventos leídos de {len(uploaded)} archivo(s)")

with tab_demo:
    st.info("Logs simulados de una empresa de Comercio Exterior (declaraciones DUA, ERP aduanero, portal de importaciones, SIEM, Active Directory).")
    if st.button("▶ Ejecutar análisis con logs demo", type="primary"):
        sdir = ROOT / "samples"
        sample_files = list(sdir.glob("sample_*.log")) + list(sdir.glob("sample_*.csv"))
        if not sample_files:
            import subprocess
            subprocess.run([sys.executable, str(sdir / "generate_samples.py")], check=True)
        parser = LogParser()
        entries = parser.parse_path(str(sdir))
        source_label = "Logs Demo — Comercio Exterior"
        st.success(f"✅ {parser.stats['parsed_ok']:,} eventos procesados")
        st.session_state.update({"entries": entries, "source": source_label})

with tab_paste:
    pasted = st.text_area("Pega el contenido de tu log:", height=180,
        placeholder="Jan  1 10:00:00 srv sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2")
    if st.button("▶ Analizar texto", type="primary") and pasted.strip():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tf:
            tf.write(pasted); tf_path = tf.name
        parser = LogParser()
        entries = parser.parse_path(tf_path)
        os.unlink(tf_path)
        source_label = "Texto pegado"
        st.success(f"✅ {len(entries):,} eventos leídos")

if not entries and "entries" in st.session_state:
    entries = st.session_state["entries"]
    source_label = st.session_state.get("source","")

# ────────────────────────────────────────────────────────────────────────────
# ANÁLISIS Y GRÁFICOS
# ────────────────────────────────────────────────────────────────────────────
if not entries:
    st.divider()
    st.markdown("### ¿Cómo usar esta herramienta?")
    st.markdown("""
1. **Sube tus logs** o usa el botón **Demo** para ver un ejemplo inmediato.
2. La herramienta clasifica los eventos según los **6 dominios ISO 27001**.
3. Calcula el **nivel de madurez COBIT (0–5)** con gráficos detallados.
4. Descarga el reporte en **HTML o JSON** para tu tesis.
    """)
    for i, (key, dom) in enumerate(ISO27001_DOMAINS.items()):
        with st.expander(f"{dom.id} — {dom.name}  (peso {dom.weight:.0%})"):
            st.caption(dom.description)
    st.stop()

# Pipeline
with st.spinner("Clasificando eventos y calculando madurez…"):
    domain_stats = EventClassifier().classify(entries)
    result = MaturityScorer().score(domain_stats)

lvl      = result.overall_level
lvl_info = MATURITY_LEVELS[lvl]
lc       = level_color(lvl)
domains  = list(result.domain_scores.values())
dom_names = [d.domain_name for d in domains]

# ── KPIs ──────────────────────────────────────────────────────────────────────
st.divider()
c1,c2,c3,c4,c5,c6 = st.columns(6)
kpis = [
    (f"{result.overall_score:.1f}/100", "SCORE GLOBAL", lc),
    (f"Nivel {lvl}", lvl_info["name"][:16], lc),
    (f"{result.total_events:,}", "EVENTOS TOTALES", C["primary"]),
    (f"{result.total_risk_events:,}", "EVENTOS DE RIESGO", C["danger"]),
    (f"{result.total_domains_active}/{len(domain_stats)}", "DOMINIOS ACTIVOS", C["success"]),
    (f"{result.total_risk_events/max(result.total_events,1):.1%}", "TASA DE RIESGO", C["warning"]),
]
for col, (val, lbl, color) in zip([c1,c2,c3,c4,c5,c6], kpis):
    with col:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-val" style="color:{color}">{val}</div>'
            f'<div class="kpi-lbl">{lbl}</div></div>',
            unsafe_allow_html=True,
        )

# ════════════════════════════════════════════════════════
# FILA 1: Gauge + Radar
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">📊 Resultado Global</div>', unsafe_allow_html=True)
col_gauge, col_radar = st.columns([1, 1.2])

# ── GRÁFICO 1: Gauge / Medidor de madurez ────────────────────────────────────
with col_gauge:
    st.markdown("#### 🎯 Medidor de Nivel de Madurez")
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=result.overall_score,
        delta={"reference": 60, "valueformat":".1f", "suffix":" pts"},
        title={"text": f"<b>Nivel {lvl} — {lvl_info['name']}</b><br><span style='font-size:.8em;color:#555'>{source_label}</span>", "font":{"size":15}},
        number={"suffix": " / 100", "font":{"size":36, "color": lc}},
        gauge={
            "axis": {"range":[0,100], "tickwidth":1, "tickcolor":"#333",
                     "tickvals":[0,20,40,60,80,100],
                     "ticktext":["0\nNivel 0","20\nNivel 1","40\nNivel 2","60\nNivel 3","80\nNivel 4","100\nNivel 5"]},
            "bar":  {"color": lc, "thickness":0.3},
            "bgcolor": "white",
            "borderwidth": 2,
            "bordercolor": "#ccc",
            "steps": [
                {"range":[0,20],  "color":"#FFCDD2"},
                {"range":[20,40], "color":"#FFE0B2"},
                {"range":[40,60], "color":"#FFF9C4"},
                {"range":[60,80], "color":"#C8E6C9"},
                {"range":[80,100],"color":"#A5D6A7"},
            ],
            "threshold": {"line":{"color":lc,"width":4}, "thickness":0.75, "value":result.overall_score},
        }
    ))
    fig_gauge.update_layout(height=320, margin=dict(l=20,r=20,t=60,b=10), paper_bgcolor="white")
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.markdown(f'<div style="background:{lc}18;border:1px solid {lc}44;border-radius:8px;padding:10px 14px;font-size:.88em;color:#333">'
                f'<b style="color:{lc}">ℹ {lvl_info["name"]}</b><br>{lvl_info["description"]}</div>', unsafe_allow_html=True)

# ── GRÁFICO 2: Radar / Spider de dominios ISO 27001 ──────────────────────────
with col_radar:
    st.markdown("#### 🕸 Radar de Dominios ISO 27001")
    scores_radar = [d.raw_score for d in domains]
    labels_radar = [f"A.{ISO27001_DOMAINS[d.domain_key].id.split('A.')[1]}<br>{d.domain_name}" for d in domains]

    fig_radar = go.Figure()
    fig_radar.add_trace(go.Scatterpolar(
        r=scores_radar + [scores_radar[0]],
        theta=labels_radar + [labels_radar[0]],
        fill="toself",
        fillcolor=hex_rgba(C["primary"], 0.2),
        line=dict(color=C["primary"], width=2.5),
        name="Score por dominio",
        hovertemplate="<b>%{theta}</b><br>Score: %{r:.1f}/100<extra></extra>",
    ))
    # Añadir anillo de referencia nivel 3 (60 pts)
    fig_radar.add_trace(go.Scatterpolar(
        r=[60]*len(labels_radar) + [60],
        theta=labels_radar + [labels_radar[0]],
        mode="lines",
        line=dict(color="#FBC02D", width=1.5, dash="dot"),
        name="Referencia Nivel 3 (60 pts)",
        hoverinfo="skip",
    ))
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0,100], tickfont=dict(size=9),
                            gridcolor="#E8EAF6", tickvals=[20,40,60,80,100]),
            angularaxis=dict(tickfont=dict(size=10)),
            bgcolor="white",
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.15, x=0.5, xanchor="center"),
        height=360,
        margin=dict(l=60, r=60, t=40, b=60),
        paper_bgcolor="white",
    )
    st.plotly_chart(fig_radar, use_container_width=True)

# ════════════════════════════════════════════════════════
# FILA 2: Barras comparativas + Desglose componentes
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">📋 Análisis por Dominio ISO 27001</div>', unsafe_allow_html=True)
col_bar1, col_bar2 = st.columns(2)

# ── GRÁFICO 3: Barras riesgo vs seguro por dominio ────────────────────────────
with col_bar1:
    st.markdown("#### ⚠ Eventos de Riesgo vs Seguros por Dominio")
    dom_keys = list(domain_stats.keys())
    dom_names_short = [d.domain_name.replace("Seguridad en ","Seg. ").replace("Gestión de ","Gest. ")[:24] for d in domains]
    safe_counts = [domain_stats[k].indicator_events for k in dom_keys]
    risk_counts = [domain_stats[k].risk_events      for k in dom_keys]

    fig_bar = go.Figure()
    fig_bar.add_trace(go.Bar(
        name="Eventos Seguros", x=dom_names_short, y=safe_counts,
        marker_color=hex_rgba(C["success"], 0.8),
        hovertemplate="<b>%{x}</b><br>Eventos seguros: %{y}<extra></extra>",
    ))
    fig_bar.add_trace(go.Bar(
        name="Eventos de Riesgo", x=dom_names_short, y=risk_counts,
        marker_color=hex_rgba(C["danger"], 0.8),
        hovertemplate="<b>%{x}</b><br>Eventos de riesgo: %{y}<extra></extra>",
    ))
    fig_bar.update_layout(
        barmode="group",
        height=320,
        margin=dict(l=10,r=10,t=20,b=80),
        paper_bgcolor="white", plot_bgcolor="white",
        legend=dict(orientation="h", y=-0.35, x=0.5, xanchor="center"),
        yaxis=dict(title="N° eventos", gridcolor="#F0F0F0"),
        xaxis=dict(tickangle=-25),
    )
    st.plotly_chart(fig_bar, use_container_width=True)

# ── GRÁFICO 4: Desglose de componentes del score (stacked horizontal bar) ─────
with col_bar2:
    st.markdown("#### 🔬 Desglose del Score por Componente")
    comps = ["Presencia de Logs","Efectividad de Controles","Ajuste Severidad","Cobertura"]
    comp_keys = ["logging_presence","control_effectiveness","severity_adjustment","coverage_bonus"]
    comp_colors = [C["primary"],"#00897B","#FB8C00","#8E24AA"]

    fig_stack = go.Figure()
    for comp, key, color in zip(comps, comp_keys, comp_colors):
        vals = [max(0, d.breakdown.get(key, 0)) for d in domains]
        fig_stack.add_trace(go.Bar(
            name=comp, y=dom_names_short, x=vals,
            orientation="h", marker_color=hex_rgba(color, 0.8),
            hovertemplate=f"<b>%{{y}}</b><br>{comp}: %{{x:.1f}} pts<extra></extra>",
        ))
    fig_stack.update_layout(
        barmode="stack", height=320,
        margin=dict(l=10,r=10,t=20,b=80),
        paper_bgcolor="white", plot_bgcolor="white",
        legend=dict(orientation="h", y=-0.35, x=0.5, xanchor="center"),
        xaxis=dict(title="Puntos", range=[0,100], gridcolor="#F0F0F0"),
    )
    st.plotly_chart(fig_stack, use_container_width=True)

# ════════════════════════════════════════════════════════
# FILA 3: Score barras + Pie distribución
# ════════════════════════════════════════════════════════
col_scores, col_pie = st.columns([1.4, 1])

# ── GRÁFICO 5: Score por dominio (barras horizontales con colores de nivel) ───
with col_scores:
    st.markdown("#### 📊 Score y Nivel por Dominio")
    sorted_domains = sorted(domains, key=lambda d: d.raw_score)
    bar_colors  = [level_color(d.level) for d in sorted_domains]
    bar_names   = [f"{d.domain_name} ({d.clause.split('–')[0].strip()})" for d in sorted_domains]
    bar_scores  = [d.raw_score for d in sorted_domains]
    bar_levels  = [f"Nivel {d.level} — {d.level_name}" for d in sorted_domains]

    fig_h = go.Figure()
    fig_h.add_trace(go.Bar(
        y=bar_names, x=bar_scores, orientation="h",
        marker_color=bar_colors,
        text=[f"{s:.1f}" for s in bar_scores],
        textposition="outside",
        customdata=bar_levels,
        hovertemplate="<b>%{y}</b><br>Score: %{x:.1f}/100<br>%{customdata}<extra></extra>",
    ))
    # Líneas de referencia de niveles
    for threshold, label, color in [(20,"Nivel 1","#D32F2F"),(40,"Nivel 2","#F57C00"),(60,"Nivel 3","#FBC02D"),(80,"Nivel 4","#388E3C")]:
        fig_h.add_vline(x=threshold, line_dash="dot", line_color=color, line_width=1.5,
                        annotation_text=label, annotation_position="top",
                        annotation_font=dict(size=9, color=color))
    fig_h.update_layout(
        height=340, margin=dict(l=10,r=60,t=30,b=10),
        paper_bgcolor="white", plot_bgcolor="white",
        xaxis=dict(range=[0,110], title="Score (0–100)", gridcolor="#F0F0F0"),
        showlegend=False,
    )
    st.plotly_chart(fig_h, use_container_width=True)

# ── GRÁFICO 6: Pie distribución de eventos por dominio ────────────────────────
with col_pie:
    st.markdown("#### 🥧 Distribución de Eventos por Dominio")
    pie_vals  = [domain_stats[d.domain_key].total_events for d in domains]
    pie_names = [d.domain_name.replace("Seguridad en ","Seg. ").replace("Gestión de ","Gest. ")[:22] for d in domains]
    fig_pie = go.Figure(go.Pie(
        labels=pie_names, values=pie_vals,
        marker=dict(colors=C["domains"], line=dict(color="white", width=2)),
        hole=0.45,
        hovertemplate="<b>%{label}</b><br>Eventos: %{value:,}<br>%{percent}<extra></extra>",
        textinfo="percent+label",
        textfont=dict(size=10),
        pull=[0.05 if domain_stats[d.domain_key].risk_events/max(domain_stats[d.domain_key].total_events,1) > 0.3 else 0 for d in domains],
    ))
    fig_pie.update_layout(
        height=340, margin=dict(l=10,r=10,t=30,b=30),
        paper_bgcolor="white",
        annotations=[dict(text=f"<b>{result.total_events:,}</b><br>eventos", x=0.5, y=0.5,
                          font_size=12, showarrow=False)],
        showlegend=False,
    )
    st.plotly_chart(fig_pie, use_container_width=True)

# ════════════════════════════════════════════════════════
# FILA 4: Heatmap de riesgo + Sunburst
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">🔥 Mapa de Riesgo y Estructura de Eventos</div>', unsafe_allow_html=True)
col_heat, col_sun = st.columns(2)

# ── GRÁFICO 7: Heatmap tasa de riesgo ────────────────────────────────────────
with col_heat:
    st.markdown("#### 🌡 Mapa de Calor — Tasa de Riesgo por Dominio")
    categories = ["Tasa Riesgo %","Score (inv.)","Eventos Críticos","Cobertura IPs"]
    dom_short = [d.domain_name.replace("Seguridad en ","").replace("Gestión de ","")[:18] for d in domains]

    heat_data = []
    for d in domains:
        ds = domain_stats[d.domain_key]
        rrate   = round(ds.risk_rate * 100, 1)
        inv_sc  = round(100 - d.raw_score, 1)
        crit    = min(100, ds.critical_events * 10)
        cov_ips = min(100, len(ds.unique_ips) * 5)
        heat_data.append([rrate, inv_sc, crit, cov_ips])

    df_heat = pd.DataFrame(heat_data, index=dom_short, columns=categories)

    fig_heat = go.Figure(go.Heatmap(
        z=df_heat.values.tolist(),
        x=categories, y=dom_short,
        colorscale=[
            [0.0,"#E8F5E9"],[0.25,"#FFF9C4"],[0.5,"#FFE0B2"],
            [0.75,"#FFCDD2"],[1.0,"#B71C1C"],
        ],
        text=[[f"{v:.0f}" for v in row] for row in df_heat.values.tolist()],
        texttemplate="%{text}",
        textfont=dict(size=11),
        hovertemplate="<b>%{y}</b><br>%{x}: %{z:.1f}<extra></extra>",
        showscale=True,
        colorbar=dict(title="Nivel<br>riesgo", tickfont=dict(size=9)),
    ))
    fig_heat.update_layout(
        height=330, margin=dict(l=10,r=10,t=20,b=10),
        paper_bgcolor="white", plot_bgcolor="white",
        xaxis=dict(tickangle=-15, tickfont=dict(size=10)),
        yaxis=dict(tickfont=dict(size=10)),
    )
    st.plotly_chart(fig_heat, use_container_width=True)
    st.caption("🔴 Rojo = mayor riesgo/exposición · 🟢 Verde = menor riesgo · Valores en escala 0–100")

# ── GRÁFICO 8: Sunburst eventos ───────────────────────────────────────────────
with col_sun:
    st.markdown("#### 🌞 Estructura Jerárquica de Eventos")
    sun_ids, sun_labels, sun_parents, sun_vals, sun_colors = [], [], [], [], []

    sun_ids.append("root"); sun_labels.append("Total\nEventos"); sun_parents.append("")
    sun_vals.append(result.total_events); sun_colors.append(C["primary"])

    for i, (key, d) in enumerate(zip(list(domain_stats.keys()), domains)):
        ds = domain_stats[key]
        if ds.total_events == 0: continue
        did = f"dom_{key}"
        sun_ids.append(did); sun_labels.append(d.domain_name.replace("Seguridad en ","Seg.\n").replace("Gestión de ","Gest.\n")[:20])
        sun_parents.append("root"); sun_vals.append(ds.total_events); sun_colors.append(C["domains"][i % len(C["domains"])])

        if ds.indicator_events > 0:
            sun_ids.append(f"{did}_ok"); sun_labels.append("Seguros")
            sun_parents.append(did); sun_vals.append(ds.indicator_events); sun_colors.append("#66BB6A")
        if ds.risk_events > 0:
            sun_ids.append(f"{did}_risk"); sun_labels.append("Riesgo")
            sun_parents.append(did); sun_vals.append(ds.risk_events); sun_colors.append("#EF5350")

    fig_sun = go.Figure(go.Sunburst(
        ids=sun_ids, labels=sun_labels, parents=sun_parents, values=sun_vals,
        marker=dict(colors=sun_colors, line=dict(width=1.5, color="white")),
        branchvalues="total",
        hovertemplate="<b>%{label}</b><br>Eventos: %{value:,}<extra></extra>",
        textfont=dict(size=10),
        insidetextorientation="radial",
    ))
    fig_sun.update_layout(
        height=350, margin=dict(l=0,r=0,t=10,b=10),
        paper_bgcolor="white",
    )
    st.plotly_chart(fig_sun, use_container_width=True)
    st.caption("🟢 Verde = eventos seguros · 🔴 Rojo = eventos de riesgo · Por dominio ISO 27001")

# ════════════════════════════════════════════════════════
# FILA 5: Histograma de niveles + Progresión
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">📈 Distribución de Niveles y Análisis de Brechas</div>', unsafe_allow_html=True)
col_hist, col_prog = st.columns([1, 1.2])

# ── GRÁFICO 9: Histograma distribución de niveles por dominio ────────────────
with col_hist:
    st.markdown("#### 📊 Distribución de Dominios por Nivel COBIT")
    level_names = [f"Nivel {i}\n{MATURITY_LEVELS[i]['name'][:12]}" for i in range(6)]
    level_counts = [sum(1 for d in domains if d.level == i) for i in range(6)]
    level_pcts   = [c/len(domains)*100 for c in level_counts]
    bar_c        = [level_color(i) for i in range(6)]

    fig_hist = go.Figure(go.Bar(
        x=level_names, y=level_counts,
        marker_color=bar_c,
        text=[f"{p:.0f}%<br>({c} dom.)" for p,c in zip(level_pcts,level_counts)],
        textposition="outside",
        hovertemplate="<b>%{x}</b><br>Dominios: %{y}<br>%{text}<extra></extra>",
    ))
    fig_hist.update_layout(
        height=300, margin=dict(l=10,r=10,t=30,b=10),
        paper_bgcolor="white", plot_bgcolor="white",
        yaxis=dict(title="N° de dominios", dtick=1, gridcolor="#F0F0F0", range=[0, len(domains)+0.5]),
        xaxis=dict(tickfont=dict(size=9)),
        showlegend=False,
    )
    st.plotly_chart(fig_hist, use_container_width=True)

# ── GRÁFICO 10: Análisis de brecha — distancia a nivel 5 ─────────────────────
with col_prog:
    st.markdown("#### 🚀 Análisis de Brecha — Distancia al Nivel 5 (100 pts)")
    target = 100
    gap_names  = [d.domain_name.replace("Seguridad en ","Seg. ").replace("Gestión de ","Gest. ")[:26] for d in domains]
    gap_actual = [d.raw_score for d in domains]
    gap_needed = [max(0, target - d.raw_score) for d in domains]

    fig_gap = go.Figure()
    fig_gap.add_trace(go.Bar(
        name="Score actual", y=gap_names, x=gap_actual, orientation="h",
        marker_color=[level_color(d.level) for d in domains],
        hovertemplate="<b>%{y}</b><br>Score actual: %{x:.1f}<extra></extra>",
    ))
    fig_gap.add_trace(go.Bar(
        name="Brecha al Nivel 5", y=gap_names, x=gap_needed, orientation="h",
        marker_color="#ECEFF1",
        marker_line=dict(color="#B0BEC5", width=1),
        hovertemplate="<b>%{y}</b><br>Brecha: %{x:.1f} pts<extra></extra>",
    ))
    fig_gap.update_layout(
        barmode="stack", height=310,
        margin=dict(l=10,r=10,t=20,b=50),
        paper_bgcolor="white", plot_bgcolor="white",
        legend=dict(orientation="h", y=-0.18, x=0.5, xanchor="center"),
        xaxis=dict(title="Puntos", range=[0,100], gridcolor="#F0F0F0"),
    )
    st.plotly_chart(fig_gap, use_container_width=True)
    st.caption(f"Brecha global al Nivel 5: **{100-result.overall_score:.1f} pts** — Score actual: {result.overall_score:.1f}/100")

# ════════════════════════════════════════════════════════
# Hallazgos y Recomendaciones
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">🚨 Hallazgos Críticos y Recomendaciones</div>', unsafe_allow_html=True)
col_find, col_rec = st.columns(2)

with col_find:
    st.markdown("#### ⚠ Hallazgos Críticos")
    if result.critical_findings:
        for f in result.critical_findings:
            st.markdown(f'<div class="finding">⚠ {f}</div>', unsafe_allow_html=True)
    else:
        st.success("✅ Sin hallazgos críticos.")

with col_rec:
    st.markdown("#### 💡 Recomendaciones")
    for i, rec in enumerate(result.recommendations, 1):
        st.markdown(f'<div class="rec">{i}. {rec}</div>', unsafe_allow_html=True)

# ════════════════════════════════════════════════════════
# Tabla de resumen detallado
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">📋 Tabla Resumen por Dominio</div>', unsafe_allow_html=True)
table_data = []
for key, d in result.domain_scores.items():
    ds = domain_stats[key]
    table_data.append({
        "Dominio": d.domain_name,
        "Cláusula": d.clause.split("–")[0].strip(),
        "Peso": f"{d.weight:.0%}",
        "Score": f"{d.raw_score:.1f}",
        "Nivel": f"{d.level} — {d.level_name}",
        "Total Eventos": ds.total_events,
        "Riesgo": ds.risk_events,
        "Tasa Riesgo": f"{ds.risk_rate:.1%}",
        "IPs Únicas": len(ds.unique_ips),
        "Usuarios": len(ds.unique_users),
    })
df_table = pd.DataFrame(table_data).sort_values("Score", ascending=False)
st.dataframe(df_table, use_container_width=True, hide_index=True)

# ════════════════════════════════════════════════════════
# Descargas
# ════════════════════════════════════════════════════════
st.markdown('<div class="section-hdr">💾 Exportar Resultados</div>', unsafe_allow_html=True)
dl1, dl2 = st.columns(2)

with dl1:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        export_html(result, source_label, tf.name)
        html_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("⬇ Descargar Reporte HTML", data=html_bytes,
        file_name="reporte_madurez_iso27001.html", mime="text/html", use_container_width=True, type="primary")

with dl2:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        export_json(result, tf.name)
        json_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("⬇ Descargar Datos JSON", data=json_bytes,
        file_name="resultado_madurez_iso27001.json", mime="application/json", use_container_width=True)

st.markdown(f"""
<footer>
  🛡 Evaluador de Madurez en Seguridad de la Información · ISO/IEC 27001:2013 · COBIT 5 · NTP ISO/IEC 27001:2008<br>
  Fuente analizada: <b>{source_label}</b> · Eventos procesados: <b>{result.total_events:,}</b>
</footer>
""", unsafe_allow_html=True)
