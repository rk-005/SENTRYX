"""
SENTRYX  dashboard/Dashboard.py  v4.0
AI Security Operations Center  Streamlit UI

Run:
    py -3.12 -m streamlit run Dashboard/Dashboard.py
Backend:
    py -3.12 server.py
"""
import streamlit as st
from datetime import datetime

try:
    from . import api_client as api
    from . import charts
except ImportError:
    import api_client as api
    import charts

# 
# PAGE CONFIG
# 
st.set_page_config(
    page_title="SENTRYX - AI Security Operations Center",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# 
# CSS
# 
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap');

:root {
  --bg:      #0b1220;
  --surface: rgba(20,30,50,0.65);
  --raised:  #121c31;
  --border:  rgba(0,255,255,0.10);
  --glow:    rgba(0,234,255,0.28);
  --text:    #e6f1ff;
  --muted:   #7f96b8;
  --blue:    #00eaff;
  --cyan:    #59fff3;
  --green:   #00e676;
  --yellow:  #ffd60a;
  --red:     #ff3b3b;
}

html, body, [class*="css"] {
  background-color: var(--bg) !important;
  color: var(--text) !important;
  font-family: 'Rajdhani', sans-serif !important;
}
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }
section[data-testid="stSidebar"] { display: none; }
.block-container { padding: 0 14px 14px !important; max-width: 100% !important; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-thumb { background: var(--glow); border-radius: 2px; }

/*  Nav  */
.nav {
  display:flex; align-items:center; justify-content:space-between;
  padding:14px 22px;
  background:rgba(10,17,30,0.92);
  border:1px solid var(--border); border-radius:12px;
  margin:8px 0 12px;
  backdrop-filter:blur(14px);
  box-shadow:0 0 22px rgba(0,234,255,0.07);
}
.nav-logo {
  font-family:'Share Tech Mono',monospace;
  font-size:26px; letter-spacing:6px; color:var(--blue);
  text-shadow:0 0 18px rgba(0,234,255,0.5);
}
.nav-sub {
  font-size:10px; letter-spacing:3px; color:var(--muted);
  font-family:'Share Tech Mono',monospace; margin-top:3px;
}
.nav-badges { display:flex; gap:8px; align-items:center; }
.badge {
  font-family:'Share Tech Mono',monospace; font-size:10px;
  padding:5px 12px; border-radius:999px; letter-spacing:2px;
}
.badge-live { background:rgba(0,230,118,0.10); color:var(--green); border:1px solid rgba(0,230,118,0.3); }
.badge-sys  { background:rgba(0,234,255,0.08); color:var(--blue);  border:1px solid rgba(0,234,255,0.2); }
.badge-off  { background:rgba(255,59,59,0.10);  color:var(--red);   border:1px solid rgba(255,59,59,0.3); }
.dot-on  { display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:5px;animation:blink 2s infinite; }
.dot-off { display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--red);margin-right:5px; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.35} }

/*  KPI strip  */
.kpi-strip {
  display:grid; grid-template-columns:repeat(6,1fr); gap:10px;
  margin-bottom:12px;
}
.kpi-card {
  background:var(--surface); border:1px solid var(--border);
  border-radius:10px; padding:12px 14px; position:relative; overflow:hidden;
}
.kpi-card::before {
  content:''; position:absolute; top:0; left:0; right:0; height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,234,255,0.35),transparent);
}
.kpi-label { font-family:'Share Tech Mono',monospace; font-size:9px; letter-spacing:3px; color:var(--muted); margin-bottom:6px; }
.kpi-value { font-family:'Share Tech Mono',monospace; font-size:22px; color:var(--blue); }
.kpi-sub   { font-family:'Share Tech Mono',monospace; font-size:9px; color:var(--muted); margin-top:3px; letter-spacing:1px; }

/*  Card  */
.card {
  background:var(--surface);
  border-radius:12px; padding:16px;
  border:1px solid var(--border);
  box-shadow:0 0 10px rgba(0,255,255,0.04);
  margin-bottom:12px; position:relative; overflow:hidden;
}
.card::before {
  content:''; position:absolute; top:0; left:0; right:0; height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,234,255,0.35),transparent);
}
.card-title {
  font-family:'Share Tech Mono',monospace;
  font-size:10px; letter-spacing:3px; color:var(--blue);
  text-transform:uppercase; margin-bottom:10px;
  padding-bottom:7px; border-bottom:1px solid rgba(0,234,255,0.07);
}

/*  Pill  */
.pill {
  display:inline-flex; align-items:center; gap:4px;
  padding:5px 13px; border-radius:4px;
  font-family:'Share Tech Mono',monospace;
  font-size:11px; letter-spacing:2px; font-weight:700;
  margin:0 5px 5px 0;
}
.p-green  { background:rgba(0,230,118,0.10); color:var(--green);  border:1px solid rgba(0,230,118,0.3); }
.p-yellow { background:rgba(255,214,10,0.10); color:var(--yellow); border:1px solid rgba(255,214,10,0.3); }
.p-red    { background:rgba(255,59,59,0.10);  color:var(--red);    border:1px solid rgba(255,59,59,0.3); }
.p-blue   { background:rgba(0,234,255,0.08);  color:var(--blue);   border:1px solid rgba(0,234,255,0.2); }

/*  Alert  */
.alert {
  display:flex; gap:11px; align-items:flex-start;
  padding:12px 15px; border-radius:6px; margin:10px 0;
  font-family:'Share Tech Mono',monospace; font-size:11px; letter-spacing:1px; line-height:1.5;
}
.a-crit { background:rgba(255,59,59,0.07);  border-left:3px solid var(--red);    color:#ff7a7a;
          animation:pulse-r 2s ease-in-out infinite; }
.a-warn { background:rgba(255,214,10,0.07); border-left:3px solid var(--yellow); color:var(--yellow); }
.a-safe { background:rgba(0,230,118,0.06);  border-left:3px solid var(--green);  color:var(--green); }
@keyframes pulse-r { 0%,100%{box-shadow:none} 50%{box-shadow:0 0 12px 2px rgba(255,59,59,0.13)} }

/*  Entity tags  */
.entity-grid { display:flex; flex-wrap:wrap; gap:7px; margin-top:6px; }
.entity-tag {
  background:rgba(255,59,59,0.09); color:#ff8080;
  border:1px solid rgba(255,59,59,0.3);
  padding:4px 12px; border-radius:4px;
  font-family:'Share Tech Mono',monospace; font-size:11px; letter-spacing:1px;
}
.entity-none {
  color:var(--muted); font-family:'Share Tech Mono',monospace; font-size:11px; letter-spacing:2px;
}

/*  Reason  */
.reason-box {
  background:rgba(0,0,0,0.25); border:1px solid var(--border);
  border-left:3px solid var(--blue);
  padding:11px 14px; border-radius:5px;
  color:var(--muted); font-size:14px; line-height:1.6;
}

/*  Timeline  */
.tl-head, .tl-row {
  display:grid;
  grid-template-columns:26px 1fr 64px 44px 54px;
  gap:10px; align-items:center;
  padding:7px 12px; font-size:13px;
}
.tl-head { font-family:'Share Tech Mono',monospace; font-size:9px; letter-spacing:2px; color:var(--muted); border-bottom:1px solid rgba(0,234,255,0.07); padding-bottom:5px; margin-bottom:4px; }
.tl-row  { background:rgba(0,0,0,0.2); border:1px solid var(--border); border-radius:5px; margin-bottom:4px; transition:border-color 0.2s; }
.tl-row:hover { border-color:var(--glow); }
.tl-idx  { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--muted); }
.tl-p    { color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.tl-a    { font-family:'Share Tech Mono',monospace; font-size:10px; letter-spacing:1px; text-align:center; padding:2px 5px; border-radius:3px; }
.tl-r    { font-family:'Share Tech Mono',monospace; font-size:11px; text-align:right; }
.tl-ts   { font-family:'Share Tech Mono',monospace; font-size:10px; color:var(--muted); text-align:right; }

/*  Reward box  */
.reward-box {
  display:flex; align-items:center; gap:14px;
  background:rgba(0,234,255,0.05); border:1px solid rgba(0,234,255,0.13);
  border-radius:6px; padding:10px 14px; margin-top:10px;
}
.reward-label { font-family:'Share Tech Mono',monospace; font-size:9px; letter-spacing:3px; color:var(--muted); }
.reward-value { font-family:'Share Tech Mono',monospace; font-size:24px; }

/*  Idle state  animated scanner  */
.idle-panel {
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  padding:32px 20px; gap:14px;
}
.scanner-ring {
  width:80px; height:80px; border-radius:50%;
  border:2px solid rgba(0,234,255,0.15);
  border-top:2px solid var(--blue);
  animation:spin 2.4s linear infinite;
  position:relative; display:flex; align-items:center; justify-content:center;
}
.scanner-ring::after {
  content:'';
  width:18px; height:18px; border-radius:50%;
  background:rgba(0,234,255,0.18);
  box-shadow:0 0 12px rgba(0,234,255,0.25);
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes counter-spin { to { transform: rotate(-360deg); } }
.idle-label {
  font-family:'Share Tech Mono',monospace; font-size:11px;
  letter-spacing:3px; color:var(--muted); text-align:center;
}
.idle-sub {
  font-family:'Share Tech Mono',monospace; font-size:9px;
  letter-spacing:2px; color:rgba(127,150,184,0.5); text-align:center;
}

/*  Divider  */
.divider { height:1px; background:linear-gradient(90deg,transparent,var(--glow),transparent); margin:12px 0; }

/*  Streamlit overrides  */
.stButton > button {
  width:100% !important;
  background:linear-gradient(135deg,#003370,#0058b0) !important;
  color:#daeeff !important; border:1px solid #1a4e8c !important;
  font-family:'Share Tech Mono',monospace !important;
  letter-spacing:3px !important; font-size:12px !important;
  padding:12px 0 !important; border-radius:6px !important;
  box-shadow:0 0 14px rgba(0,88,176,0.28) !important;
  transition:all 0.2s ease !important;
}
.stButton > button:hover {
  box-shadow:0 0 26px rgba(0,234,255,0.38) !important;
  border-color:var(--blue) !important;
}
.stTextArea textarea {
  background:rgba(0,0,0,0.35) !important; border:1px solid var(--border) !important;
  color:var(--text) !important; font-family:'Rajdhani',sans-serif !important;
  font-size:14px !important; border-radius:6px !important;
}
.stTextArea textarea:focus { border-color:var(--blue) !important; box-shadow:0 0 8px rgba(0,234,255,0.18) !important; }
.stTextArea label, .stSelectbox label {
  font-family:'Share Tech Mono',monospace !important;
  font-size:10px !important; letter-spacing:2px !important; color:var(--muted) !important;
}
.stSelectbox > div > div { background:var(--raised) !important; border:1px solid var(--border) !important; color:var(--text) !important; }
[data-testid="metric-container"] { background:var(--raised) !important; border:1px solid var(--border) !important; border-radius:7px !important; padding:12px !important; }
[data-testid="metric-container"] label { font-family:'Share Tech Mono',monospace !important; font-size:9px !important; letter-spacing:3px !important; color:var(--muted) !important; }
[data-testid="stMetricValue"] { font-family:'Share Tech Mono',monospace !important; font-size:26px !important; }
.stProgress > div > div > div { background:linear-gradient(90deg,#003878,var(--blue)) !important; }
.stSpinner > div { border-top-color:var(--blue) !important; }
</style>
""", unsafe_allow_html=True)

# 
# CONSTANTS
# 
TASK_META = {
    "simple_pii_detection": ("LOW", "Baseline Stability", "Easy - 3 scenarios"),
    "threat_classification": ("MED", "Business Confidentiality", "Medium - 4 scenarios"),
    "multi_step_attack": ("HIGH", "Attack Simulation", "Hard - 6 scenarios"),
}

ACTION_COLORS = {"ALLOW": "green", "MASK": "yellow", "BLOCK": "red"}
THREAT_COLORS = {"SAFE":  "green", "WARNING": "yellow", "CRITICAL": "red"}
SENS_COLORS   = {"LOW":   "green", "MEDIUM":  "yellow", "HIGH":     "red"}

_ACV = {"ALLOW": "var(--green)", "MASK": "var(--yellow)", "BLOCK": "var(--red)"}
_TCV = {"SAFE":  "var(--green)", "WARNING": "var(--yellow)", "CRITICAL": "var(--red)"}


# 
# SESSION STATE
# 
_DEFAULTS = {
    "history":    [],
    "result":     None,
    "step_count": 0,
    "backend_ok": None,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# 
# HELPERS
# 
def pill(text: str, cls: str) -> str:
    return f'<span class="pill p-{cls}">{text}</span>'


def alert_html(threat: str, action: str, reason: str) -> str:
    icon = {"CRITICAL": "CRIT", "WARNING": "WARN", "SAFE": "SAFE"}.get(threat, "INFO")
    cls  = {"CRITICAL": "a-crit", "WARNING": "a-warn", "SAFE": "a-safe"}.get(threat, "a-safe")
    snip = (reason[:180] + "...") if len(reason) > 180 else reason
    return (f'<div class="alert {cls}">'
            f'<span style="font-size:15px">{icon}</span>'
            f'<span>[{action}] {snip}</span></div>')


def tl_row_html(idx: int, h: dict) -> str:
    a  = h.get("action", "ALLOW")
    ac = _ACV.get(a, "var(--text)")
    r  = int(h.get("risk_score", 0))
    rc = _TCV.get(h.get("threat_level", "SAFE"), "var(--text)")
    p  = h.get("prompt", "")
    p  = (p[:44] + "...") if len(p) > 44 else p
    ts = h.get("ts", "")
    return (f'<div class="tl-row">'
            f'<span class="tl-idx">#{idx:02d}</span>'
            f'<span class="tl-p">{p}</span>'
            f'<span class="tl-a" style="background:{ac}22;color:{ac}">{a}</span>'
            f'<span class="tl-r" style="color:{rc}">{r}</span>'
            f'<span class="tl-ts">{ts}</span>'
            f'</div>')


def safe_entities(raw: list) -> list[str]:
    out = []
    for e in raw:
        if isinstance(e, str):
            out.append(e.replace("EntityType.", "").strip())
        elif isinstance(e, dict):
            val = e.get("type") or e.get("entity_type") or e.get("value") or str(e)
            out.append(str(val).replace("EntityType.", "").strip())
        else:
            out.append(str(e).replace("EntityType.", "").strip())
    return out


def kpi_card(label: str, value: str, sub: str = "") -> str:
    return (f'<div class="kpi-card">'
            f'<div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{value}</div>'
            + (f'<div class="kpi-sub">{sub}</div>' if sub else '')
            + '</div>')


# 
# BACKEND HEALTH CHECK
# 
if st.session_state.backend_ok is None:
    st.session_state.backend_ok = api.health_check()

backend_ok: bool = st.session_state.backend_ok

# 
# NAV BAR
# 
dot  = '<span class="dot-on"></span>ONLINE'   if backend_ok else '<span class="dot-off"></span>OFFLINE'
bdge = "badge-live"                           if backend_ok else "badge-off"

st.markdown(f"""
<div class="nav">
  <div>
    <div class="nav-logo">SENTRYX<span style="color:var(--text)">.</span></div>
    <div class="nav-sub">AI SECURITY OPERATIONS CENTER &nbsp;|&nbsp; LLM DATA LEAKAGE PREVENTION</div>
  </div>
  <div class="nav-badges">
    <div class="badge badge-sys">v4.0</div>
    <div class="badge {bdge}">{dot}</div>
  </div>
</div>
""", unsafe_allow_html=True)

if not backend_ok:
    st.error(
        "**Backend offline.** Start it with:\n\n"
        "```\npy -3.12 server.py\n```"
    )
    if st.button("RETRY CONNECTION"):
        st.session_state.backend_ok = None
        st.rerun()
    st.stop()

# 
# STATE
# 
hist       = st.session_state.history
res        = st.session_state.result
has_result = res is not None
n          = len(hist)

total  = n
blocks = sum(1 for h in hist if h.get("action") == "BLOCK")
masks  = sum(1 for h in hist if h.get("action") == "MASK")
allows = sum(1 for h in hist if h.get("action") == "ALLOW")
avg_r  = round(sum(h.get("risk_score", 0) for h in hist) / total, 1) if total else 0.0
crits  = sum(1 for h in hist if h.get("threat_level") == "CRITICAL")

# 
# KPI STRIP (always visible)
# 
last_threat = res.get("threat_level", "-") if has_result else "-"
last_risk   = f'{res.get("risk_score", 0):.0f}' if has_result else "-"
threat_col  = {"SAFE": "var(--green)", "WARNING": "var(--yellow)", "CRITICAL": "var(--red)"}.get(last_threat, "var(--blue)")

st.markdown(f"""
<div class="kpi-strip">
  {kpi_card("ANALYZED", str(total), "total prompts")}
  {kpi_card("BLOCKED", str(blocks), "threat blocked")}
  {kpi_card("MASKED", str(masks), "data masked")}
  {kpi_card("ALLOWED", str(allows), "passed")}
  {kpi_card("AVG RISK", str(avg_r), "session mean")}
  <div class="kpi-card">
    <div class="kpi-label">LAST THREAT</div>
    <div class="kpi-value" style="color:{threat_col};font-size:16px">{last_threat}</div>
    <div class="kpi-sub">risk | {last_risk}</div>
  </div>
</div>
""", unsafe_allow_html=True)

# 
# ROW 1  PRIMARY ANALYTICS: Gauge | Trend (wide) | Donut
# Always visible. Gauge shows last result or idle state. No empty blocks.
# 
r1c1, r1c2, r1c3 = st.columns([1, 2.2, 1], gap="small")

with r1c1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">RISK GAUGE</div>', unsafe_allow_html=True)
    gauge_score = float(res.get("risk_score", 0)) if has_result else 0.0
    st.plotly_chart(
        charts.risk_gauge(gauge_score),
        use_container_width=True,
        key=f"gauge_{n}",
        config={"displayModeBar": False},
    )
    st.markdown('</div>', unsafe_allow_html=True)

with r1c2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">RISK TREND</div>', unsafe_allow_html=True)
    st.plotly_chart(
        charts.risk_trend(hist),
        use_container_width=True,
        key=f"trend_{n}",
        config={"displayModeBar": False},
    )
    st.markdown('</div>', unsafe_allow_html=True)

with r1c3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">THREAT MIX</div>', unsafe_allow_html=True)
    st.plotly_chart(
        charts.threat_donut(hist),
        use_container_width=True,
        key=f"donut_{n}",
        config={"displayModeBar": False},
    )
    st.markdown('</div>', unsafe_allow_html=True)

# 
# ROW 2  DYNAMIC LAYOUT
#
#   NO RESULT  [Input (38%) | Charts panel (62%)]
#   HAS RESULT  [Input (28%) | Live Analysis (40%) | Entities+Reward (32%)]
#
# CRITICAL: Middle column is ONLY rendered when has_result is True.
# 

if has_result:
    col1, col2, col3 = st.columns([1.1, 1.6, 1.1], gap="small")
else:
    col1, col3 = st.columns([1.1, 1.9], gap="small")
    col2 = None   # explicitly None  never rendered

# 
#   COL 1  Input + session stats (always rendered)                         
# 
with col1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">INPUT TERMINAL</div>', unsafe_allow_html=True)

    st.selectbox(
        "TASK SCENARIO",
        options=list(TASK_META.keys()),
        format_func=lambda k: f"{TASK_META[k][1]} - {TASK_META[k][2]}",
        key="task_select",
    )
    st.text_area(
        "PROMPT",
        placeholder="Paste or type a user prompt to analyze for data leakage threats...",
        height=190,
        key="prompt_input",
    )
    analyze_btn = st.button("RUN THREAT ANALYSIS", key="analyze", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Session stats card
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">SESSION STATS</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.metric("ANALYZED", total)
        st.metric("MASKED",   masks)
    with c2:
        st.metric("BLOCKED",  blocks)
        st.metric("AVG RISK", f"{avg_r}")

    if has_result:
        reward = res.get("reward", 0)
        rc     = "var(--green)" if reward > 0.6 else "var(--yellow)" if reward > 0 else "var(--red)"
        st.markdown(
            f'<div class="reward-box">'
            f'<div><div class="reward-label">LAST REWARD</div>'
            f'<div class="reward-value" style="color:{rc}">{reward:+.2f}</div></div>'
            f'<div style="color:var(--muted);font-size:13px;line-height:1.5">RL signal from<br>reward engine</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    st.markdown('</div>', unsafe_allow_html=True)

# 
#   COL 2  Live Analysis (ONLY rendered when has_result is True)           
# 
if has_result and col2 is not None:
    with col2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">LIVE ANALYSIS</div>', unsafe_allow_html=True)

        risk_score  = float(res.get("risk_score", 0))
        threat      = res.get("threat_level", "SAFE")
        sensitivity = res.get("sensitivity", "LOW")
        action      = res.get("action", "ALLOW")
        raw_ents    = res.get("detected_entities", [])
        entities    = safe_entities(raw_ents)
        reason      = res.get("reason", "")
        attack_type = res.get("attack_type", "NORMAL")

        # Status pills
        tv = ACTION_COLORS.get(action, "blue")
        th = THREAT_COLORS.get(threat, "blue")
        sv = SENS_COLORS.get(sensitivity, "blue")
        st.markdown(
            pill(action, tv)
            + pill(threat, th)
            + pill(sensitivity, sv)
            + (pill(attack_type, "red") if attack_type != "NORMAL" else ""),
            unsafe_allow_html=True,
        )

        # Alert banner
        st.markdown(alert_html(threat, action, reason), unsafe_allow_html=True)

        # Detected entities
        st.markdown('<div class="card-title" style="margin-top:14px">DETECTED ENTITIES</div>', unsafe_allow_html=True)
        if entities:
            tags_html = "".join(f'<span class="entity-tag">{e}</span>' for e in entities)
            st.markdown(f'<div class="entity-grid">{tags_html}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="entity-none">NO SENSITIVE ENTITIES DETECTED</span>', unsafe_allow_html=True)

        # Reason
        st.markdown('<div class="card-title" style="margin-top:14px">ANALYSIS REASON</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="reason-box">{reason}</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

# 
#   COL 3  Charts (always rendered; wider when no result)                  
# 
with col3:
    # Action distribution
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">ACTION DISTRIBUTION</div>', unsafe_allow_html=True)
    st.plotly_chart(
        charts.action_distribution(hist),
        use_container_width=True,
        key=f"actions_{n}",
        config={"displayModeBar": False},
    )
    st.markdown('</div>', unsafe_allow_html=True)

    # Entity frequency
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">ENTITY FREQUENCY</div>', unsafe_allow_html=True)
    st.plotly_chart(
        charts.entity_frequency(hist),
        use_container_width=True,
        key=f"entity_{n}",
        config={"displayModeBar": False},
    )
    st.markdown('</div>', unsafe_allow_html=True)

    # Idle scanner  only shown when no data AND no result (truly empty state)
    if not hist and not has_result:
        st.markdown(
            '<div class="card">'
            '<div class="card-title">SYSTEM STATUS</div>'
            '<div class="idle-panel">'
            '<div class="scanner-ring"></div>'
            '<div class="idle-label">AWAITING FIRST SCAN</div>'
            '<div class="idle-sub">ENTER A PROMPT -> RUN THREAT ANALYSIS</div>'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )

# 
# ROW 3  BOTTOM: Action Distribution mini + History Timeline (wide)
# 
bot1, bot2 = st.columns([1, 2.5], gap="small")

with bot1:
    # Sparkline / mini risk card  always has content
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">RISK SPARKLINE</div>', unsafe_allow_html=True)
    st.plotly_chart(
        charts.risk_sparkline(hist),
        use_container_width=True,
        key=f"spark_{n}",
        config={"displayModeBar": False},
    )
    # Quick threat count summary
    if hist:
        safe_c  = sum(1 for h in hist if h.get("threat_level") == "SAFE")
        warn_c  = sum(1 for h in hist if h.get("threat_level") == "WARNING")
        crit_c  = sum(1 for h in hist if h.get("threat_level") == "CRITICAL")
        st.markdown(
            f'<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">'
            f'<span class="pill p-green" style="font-size:10px">SAFE {safe_c}</span>'
            f'<span class="pill p-yellow" style="font-size:10px">WARN {warn_c}</span>'
            f'<span class="pill p-red" style="font-size:10px">CRIT {crit_c}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="color:var(--muted);font-family:\'Share Tech Mono\',monospace;'
            'font-size:10px;letter-spacing:2px;padding:10px 0">NO DATA YET</div>',
            unsafe_allow_html=True,
        )
    st.markdown('</div>', unsafe_allow_html=True)

with bot2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">HISTORY TIMELINE</div>', unsafe_allow_html=True)
    if not hist:
        # Animated placeholder  no boring "no data" text
        st.markdown(
            '<div style="display:flex;align-items:center;gap:16px;padding:18px 0">'
            '<div class="scanner-ring" style="width:40px;height:40px;border-width:1.5px"></div>'
            '<div>'
            '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;'
            'letter-spacing:3px;color:var(--muted)">TIMELINE INITIALIZING</div>'
            '<div style="font-family:\'Share Tech Mono\',monospace;font-size:9px;'
            'color:rgba(127,150,184,0.4);letter-spacing:2px;margin-top:4px">'
            'EVENTS WILL APPEAR AFTER FIRST SCAN</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="tl-head">'
            '<span>#</span><span>PROMPT</span>'
            '<span>ACTION</span><span>RISK</span><span>TIME</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        rows = "".join(tl_row_html(i + 1, h) for i, h in enumerate(reversed(hist)))
        st.markdown(rows, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# 
# ANALYZE BUTTON HANDLER
# 
if analyze_btn:
    raw_prompt = st.session_state.get("prompt_input", "").strip()
    if not raw_prompt:
        st.warning("Please enter a prompt before running analysis.")
    else:
        with st.spinner("Scanning for threats..."):
            try:
                result = api.analyze(
                    prompt=raw_prompt,
                    task=st.session_state.get("task_select", "simple_pii_detection"),
                )
                result["detected_entities"] = safe_entities(
                    result.get("detected_entities", [])
                )
                result["ts"] = datetime.now().strftime("%H:%M:%S")

                st.session_state["result"]      = result
                st.session_state["step_count"] += 1
                st.session_state["history"].append(result)
                st.session_state["backend_ok"]  = True

            except api.APIError as exc:
                st.session_state["backend_ok"] = False
                st.error(f"Backend Error: {exc}")
            except Exception as exc:
                st.error(f"Unexpected error: {exc}")

        st.rerun()

# 
# FOOTER
# 
st.markdown("""
<div style="text-align:center;padding:18px 0 6px;
     font-family:'Share Tech Mono',monospace;font-size:9px;
     letter-spacing:3px;color:#162030">
  SENTRYX AI SECURITY OPERATIONS CENTER &nbsp;|&nbsp; LLM DATA LEAKAGE PREVENTION &nbsp;|&nbsp; v4.0
</div>
""", unsafe_allow_html=True)



