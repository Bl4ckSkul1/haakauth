#!/usr/bin/env python3
"""HaakAuth Report Generator — HAAK Cybersecurity"""
import json
import sys
import html
from pathlib import Path
from datetime import datetime


def load_data(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def severity_color(s: str) -> str:
    return {
        "critical": "#ff0040",
        "high": "#ff6b00",
        "medium": "#ffaa00",
        "low": "#22c55e",
        "info": "#3b82f6",
    }.get(s.lower(), "#64748b")


def severity_bg(s: str) -> str:
    return {
        "critical": "rgba(255,0,64,0.12)",
        "high": "rgba(255,107,0,0.12)",
        "medium": "rgba(255,170,0,0.12)",
        "low": "rgba(34,197,94,0.12)",
        "info": "rgba(59,130,246,0.12)",
    }.get(s.lower(), "rgba(100,116,139,0.12)")


def severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s.lower(), 5)


def calculate_risk_score(stats: dict) -> int:
    score = 100
    score -= stats.get("findings_critical", 0) * 30
    score -= stats.get("findings_high", 0) * 15
    score -= stats.get("findings_medium", 0) * 8
    score -= stats.get("findings_low", 0) * 3
    score -= stats.get("findings_info", 0) * 1
    return max(0, score)


def risk_label(score: int) -> tuple:
    if score < 30:
        return "CRITICAL", "#ff0040"
    if score < 50:
        return "POOR", "#ff6b00"
    if score < 70:
        return "FAIR", "#ffaa00"
    if score < 85:
        return "GOOD", "#22c55e"
    return "STRONG", "#00ff88"


def overall_risk(stats: dict) -> tuple:
    if stats.get("findings_critical", 0) > 0:
        return "CRITICAL", "#ff0040"
    if stats.get("findings_high", 0) > 0:
        return "HIGH", "#ff6b00"
    if stats.get("findings_medium", 0) > 0:
        return "MEDIUM", "#ffaa00"
    if stats.get("findings_low", 0) > 0:
        return "LOW", "#22c55e"
    return "INFO", "#3b82f6"


def fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    return f"{m}m {s}s"


def generate_css() -> str:
    return """
    :root {
      --bg-primary: #060a14;
      --bg-card: #0d1321;
      --bg-card2: #111827;
      --border: rgba(0,200,255,0.08);
      --border-hover: rgba(0,200,255,0.18);
      --accent: #00c8ff;
      --accent-purple: #8b5cf6;
      --critical: #ff0040;
      --high: #ff6b00;
      --medium: #ffaa00;
      --low: #22c55e;
      --info: #3b82f6;
      --text: #e2e8f0;
      --text-muted: #64748b;
      --sidebar-w: 200px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg-primary);
      color: var(--text);
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      display: flex;
    }

    /* SIDEBAR */
    .sidebar {
      width: var(--sidebar-w);
      min-height: 100vh;
      background: var(--bg-card);
      border-right: 1px solid var(--border);
      position: fixed;
      top: 0; left: 0;
      display: flex;
      flex-direction: column;
      padding: 24px 0;
      z-index: 100;
    }
    .sidebar-logo {
      padding: 0 20px 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .sidebar-logo .tool-name {
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.15em;
      background: linear-gradient(135deg, var(--accent), var(--accent-purple));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .sidebar-logo .tool-sub {
      font-size: 10px;
      color: var(--text-muted);
      margin-top: 2px;
      letter-spacing: 0.05em;
    }
    .nav-item {
      display: block;
      padding: 8px 20px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 12px;
      font-weight: 500;
      letter-spacing: 0.03em;
      border-left: 3px solid transparent;
      transition: all 0.2s;
      cursor: pointer;
    }
    .nav-item:hover, .nav-item.active {
      color: var(--accent);
      border-left-color: var(--accent);
      background: rgba(0,200,255,0.05);
    }
    .nav-section {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.12em;
      color: var(--text-muted);
      padding: 16px 20px 6px;
      text-transform: uppercase;
    }
    .sidebar-footer {
      margin-top: auto;
      padding: 16px 20px 0;
      border-top: 1px solid var(--border);
      font-size: 10px;
      color: var(--text-muted);
    }

    /* MAIN CONTENT */
    .main {
      margin-left: var(--sidebar-w);
      flex: 1;
      padding: 0 40px 60px;
      max-width: calc(100vw - var(--sidebar-w));
    }

    /* TOP ACCENT LINE */
    .top-bar {
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--accent-purple), var(--critical));
      position: fixed;
      top: 0; left: var(--sidebar-w); right: 0;
      z-index: 99;
    }

    /* HEADER */
    .report-header {
      padding: 48px 0 32px;
      border-bottom: 1px solid var(--border);
    }
    .report-header h1 {
      font-size: 36px;
      font-weight: 900;
      letter-spacing: 0.06em;
      background: linear-gradient(135deg, var(--accent), var(--accent-purple));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 4px;
    }
    .report-header .subtitle {
      font-size: 16px;
      color: var(--text-muted);
      font-weight: 400;
      margin-bottom: 24px;
    }
    .meta-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 24px;
      margin-top: 16px;
    }
    .meta-item { display: flex; flex-direction: column; gap: 2px; }
    .meta-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      text-transform: uppercase;
    }
    .meta-value {
      font-size: 13px;
      color: var(--text);
      font-weight: 500;
    }
    .meta-value.accent { color: var(--accent); }

    /* SECTION TITLES */
    .section { padding: 40px 0 0; }
    .section-title {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    /* SUMMARY CARDS */
    .summary-row {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .sev-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px 16px;
      text-align: center;
      transition: border-color 0.2s, transform 0.2s;
      position: relative;
      overflow: hidden;
    }
    .sev-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
    }
    .sev-card.critical::before { background: var(--critical); }
    .sev-card.high::before { background: var(--high); }
    .sev-card.medium::before { background: var(--medium); }
    .sev-card.low::before { background: var(--low); }
    .sev-card.info::before { background: var(--info); }
    .sev-card:hover { transform: translateY(-2px); }
    .sev-card.critical { border-color: rgba(255,0,64,0.25); }
    .sev-card.high { border-color: rgba(255,107,0,0.25); }
    .sev-card.medium { border-color: rgba(255,170,0,0.25); }
    .sev-card.low { border-color: rgba(34,197,94,0.2); }
    .sev-card.info { border-color: rgba(59,130,246,0.2); }
    .sev-count {
      font-size: 40px;
      font-weight: 900;
      line-height: 1;
      margin-bottom: 6px;
    }
    .sev-card.critical .sev-count { color: var(--critical); }
    .sev-card.high .sev-count { color: var(--high); }
    .sev-card.medium .sev-count { color: var(--medium); }
    .sev-card.low .sev-count { color: var(--low); }
    .sev-card.info .sev-count { color: var(--info); }
    .sev-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
    }

    /* OVERALL RISK BADGE */
    .overall-risk-row {
      display: flex;
      align-items: center;
      gap: 20px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 24px;
    }
    .risk-badge {
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0.12em;
      padding: 6px 16px;
      border-radius: 6px;
    }
    .overall-stats { display: flex; gap: 32px; margin-left: auto; }
    .stat-item { display: flex; flex-direction: column; align-items: center; gap: 2px; }
    .stat-num { font-size: 22px; font-weight: 700; color: var(--accent); }
    .stat-lbl { font-size: 10px; color: var(--text-muted); letter-spacing: 0.06em; text-transform: uppercase; }

    /* GAUGE */
    .gauge-wrapper {
      display: flex;
      align-items: center;
      gap: 48px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px 40px;
    }
    .gauge-container {
      position: relative;
      width: 180px;
      height: 180px;
      flex-shrink: 0;
    }
    .gauge-svg { width: 180px; height: 180px; transform: rotate(-90deg); }
    .gauge-track { fill: none; stroke: rgba(255,255,255,0.06); stroke-width: 14; stroke-linecap: round; }
    .gauge-fill { fill: none; stroke-width: 14; stroke-linecap: round; transition: stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1); }
    .gauge-center {
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .gauge-score { font-size: 36px; font-weight: 900; line-height: 1; }
    .gauge-score-label { font-size: 11px; color: var(--text-muted); letter-spacing: 0.06em; }
    .gauge-info { flex: 1; }
    .gauge-info h3 { font-size: 22px; font-weight: 800; margin-bottom: 8px; }
    .gauge-info p { color: var(--text-muted); font-size: 13px; line-height: 1.7; }
    .gauge-breakdown { margin-top: 20px; display: flex; flex-wrap: wrap; gap: 10px; }
    .gauge-chip {
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 20px;
      border: 1px solid;
      font-weight: 600;
    }

    /* MODULE CHART */
    .chart-container {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
    }
    .chart-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
    }
    .chart-label {
      width: 80px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--text-muted);
      text-align: right;
      flex-shrink: 0;
    }
    .chart-bar-track {
      flex: 1;
      height: 22px;
      background: rgba(255,255,255,0.04);
      border-radius: 4px;
      overflow: hidden;
      position: relative;
    }
    .chart-bar-fill {
      height: 100%;
      display: flex;
      border-radius: 4px;
      transition: width 0.8s ease;
    }
    .chart-meta {
      width: 100px;
      font-size: 11px;
      color: var(--text-muted);
      flex-shrink: 0;
    }
    .chart-segment { height: 100%; }

    /* FILTERS */
    .filter-bar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 20px;
      align-items: center;
    }
    .filter-btn {
      padding: 6px 14px;
      border-radius: 20px;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--text-muted);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      letter-spacing: 0.04em;
    }
    .filter-btn:hover, .filter-btn.active {
      border-color: var(--accent);
      color: var(--accent);
      background: rgba(0,200,255,0.06);
    }
    .filter-btn.f-critical.active { border-color: var(--critical); color: var(--critical); background: rgba(255,0,64,0.08); }
    .filter-btn.f-high.active { border-color: var(--high); color: var(--high); background: rgba(255,107,0,0.08); }
    .filter-btn.f-medium.active { border-color: var(--medium); color: var(--medium); background: rgba(255,170,0,0.08); }
    .filter-btn.f-low.active { border-color: var(--low); color: var(--low); background: rgba(34,197,94,0.08); }
    .filter-btn.f-info.active { border-color: var(--info); color: var(--info); background: rgba(59,130,246,0.08); }
    .search-box {
      margin-left: auto;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 12px;
      color: var(--text);
      font-size: 12px;
      outline: none;
      width: 200px;
      transition: border-color 0.2s;
    }
    .search-box:focus { border-color: var(--accent); }

    /* FINDING CARDS */
    .finding-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid;
      border-radius: 0 10px 10px 0;
      padding: 20px 24px;
      margin-bottom: 16px;
      transition: border-color 0.2s;
    }
    .finding-card.sev-critical { border-left-color: var(--critical); }
    .finding-card.sev-high { border-left-color: var(--high); }
    .finding-card.sev-medium { border-left-color: var(--medium); }
    .finding-card.sev-low { border-left-color: var(--low); }
    .finding-card.sev-info { border-left-color: var(--info); }
    .finding-card.sev-critical, .finding-card.sev-high {
      box-shadow: 0 0 20px rgba(255,0,64,0.04);
    }
    .finding-card.sev-high {
      box-shadow: 0 0 20px rgba(255,107,0,0.04);
    }
    .finding-card-header {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .badge {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 3px 10px;
      border-radius: 20px;
      flex-shrink: 0;
    }
    .badge-module {
      background: rgba(0,200,255,0.1);
      color: var(--accent);
      border: 1px solid rgba(0,200,255,0.2);
    }
    .finding-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text);
      flex: 1;
    }
    .finding-ts {
      font-size: 10px;
      color: var(--text-muted);
      margin-left: auto;
      white-space: nowrap;
    }
    .finding-desc {
      color: #94a3b8;
      font-size: 13px;
      margin-bottom: 14px;
      line-height: 1.65;
    }
    .evidence-block {
      background: #050810;
      border: 1px solid rgba(0,200,255,0.1);
      border-radius: 6px;
      padding: 12px 16px;
      font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      font-size: 12px;
      color: #a8e6cf;
      margin-bottom: 14px;
      white-space: pre-wrap;
      word-break: break-all;
      position: relative;
    }
    .evidence-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
    .copy-btn {
      position: absolute;
      top: 8px; right: 8px;
      background: rgba(0,200,255,0.1);
      border: 1px solid rgba(0,200,255,0.2);
      color: var(--accent);
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }
    .copy-btn:hover { background: rgba(0,200,255,0.2); }
    .copy-btn.copied { color: var(--low); border-color: var(--low); }

    /* COLLAPSIBLE REQUEST/RESPONSE */
    .collapsible-btn {
      display: flex;
      align-items: center;
      gap: 8px;
      background: none;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 600;
      padding: 6px 12px;
      cursor: pointer;
      transition: all 0.2s;
      letter-spacing: 0.04em;
      margin-bottom: 8px;
    }
    .collapsible-btn:hover { border-color: var(--accent); color: var(--accent); }
    .collapsible-btn .arrow { transition: transform 0.2s; }
    .collapsible-btn.open .arrow { transform: rotate(90deg); }
    .collapsible-content {
      display: none;
      margin-bottom: 14px;
    }
    .collapsible-content.open { display: block; }
    .req-resp-block {
      background: #040710;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px 16px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 11px;
      color: #cbd5e1;
      white-space: pre-wrap;
      word-break: break-all;
      position: relative;
    }
    .req-resp-block .http-method { color: var(--accent); font-weight: 700; }
    .req-resp-block .http-url { color: #c4b5fd; }
    .req-resp-block .status-2xx { color: var(--low); font-weight: 700; }
    .req-resp-block .status-4xx { color: var(--high); font-weight: 700; }
    .req-resp-block .status-5xx { color: var(--critical); font-weight: 700; }
    .req-resp-row { display: flex; gap: 12px; }
    .req-resp-col { flex: 1; min-width: 0; }
    .req-resp-col-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    /* REMEDIATION */
    .remediation-block {
      border-left: 3px solid var(--low);
      padding: 10px 16px;
      background: rgba(34,197,94,0.04);
      border-radius: 0 6px 6px 0;
      margin-bottom: 14px;
    }
    .remediation-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--low);
      margin-bottom: 4px;
    }
    .remediation-text { font-size: 12px; color: #94a3b8; line-height: 1.6; }

    /* CWE / REFS */
    .finding-footer {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }
    .cwe-link {
      font-size: 11px;
      color: var(--accent-purple);
      text-decoration: none;
      border: 1px solid rgba(139,92,246,0.3);
      padding: 3px 10px;
      border-radius: 4px;
      transition: all 0.2s;
    }
    .cwe-link:hover { background: rgba(139,92,246,0.1); }

    /* MODULE DETAILS */
    .module-accordion {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 8px;
      overflow: hidden;
    }
    .module-accordion-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 20px;
      cursor: pointer;
      transition: background 0.2s;
      user-select: none;
    }
    .module-accordion-header:hover { background: rgba(255,255,255,0.02); }
    .module-accordion-header .mod-name {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--text);
    }
    .module-accordion-header .mod-stats {
      font-size: 11px;
      color: var(--text-muted);
      margin-left: auto;
    }
    .module-accordion-header .mod-arrow { transition: transform 0.2s; color: var(--text-muted); }
    .module-accordion-header.open .mod-arrow { transform: rotate(90deg); }
    .module-accordion-body {
      display: none;
      padding: 0 20px 16px;
      border-top: 1px solid var(--border);
    }
    .module-accordion-body.open { display: block; }
    .module-desc { font-size: 12px; color: var(--text-muted); margin: 12px 0; }

    /* METHODOLOGY */
    .method-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
    }
    .method-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
    }
    .method-card-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .method-card-value { font-size: 20px; font-weight: 800; color: var(--accent); }
    .method-card-sub { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

    /* FOOTER */
    .report-footer {
      margin-top: 60px;
      padding: 24px 0;
      border-top: 1px solid var(--border);
      text-align: center;
    }
    .footer-brand {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.1em;
      color: var(--accent);
      margin-bottom: 4px;
    }
    .footer-meta { font-size: 11px; color: var(--text-muted); line-height: 1.8; }
    .footer-disclaimer {
      margin-top: 12px;
      font-size: 10px;
      color: var(--text-muted);
      max-width: 600px;
      margin-left: auto;
      margin-right: auto;
      opacity: 0.7;
    }

    /* PRINT */
    @media print {
      .sidebar, .top-bar, .filter-bar, .copy-btn, .collapsible-btn { display: none !important; }
      .main { margin-left: 0; max-width: 100%; padding: 20px; }
      .finding-card { break-inside: avoid; }
      .collapsible-content { display: block !important; }
      body { background: white; color: black; }
    }

    /* RESPONSIVE */
    @media (max-width: 900px) {
      :root { --sidebar-w: 0px; }
      .sidebar { display: none; }
      .top-bar { left: 0; }
      .main { margin-left: 0; padding: 0 20px 40px; }
      .summary-row { grid-template-columns: repeat(3, 1fr); }
    }
    """


def generate_js() -> str:
    return """
    // Filter functionality
    let activeFilter = 'all';
    let searchTerm = '';

    function setFilter(sev) {
      activeFilter = sev;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-filter="' + sev + '"]').classList.add('active');
      applyFilters();
    }

    function applyFilters() {
      document.querySelectorAll('.finding-card').forEach(card => {
        const cardSev = card.dataset.severity;
        const cardText = card.textContent.toLowerCase();
        const sevMatch = activeFilter === 'all' || cardSev === activeFilter;
        const searchMatch = searchTerm === '' || cardText.includes(searchTerm);
        card.style.display = (sevMatch && searchMatch) ? '' : 'none';
      });
    }

    document.addEventListener('DOMContentLoaded', () => {
      const searchBox = document.getElementById('findingSearch');
      if (searchBox) {
        searchBox.addEventListener('input', e => {
          searchTerm = e.target.value.toLowerCase();
          applyFilters();
        });
      }

      // Count-up animation
      document.querySelectorAll('.sev-count').forEach(el => {
        const target = parseInt(el.dataset.count || '0');
        if (target === 0) { el.textContent = '0'; return; }
        let current = 0;
        const step = Math.max(1, Math.floor(target / 30));
        const timer = setInterval(() => {
          current = Math.min(current + step, target);
          el.textContent = current;
          if (current >= target) clearInterval(timer);
        }, 30);
      });

      // Collapsible sections
      document.querySelectorAll('.collapsible-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.dataset.target;
          const content = document.getElementById(targetId);
          if (content) {
            content.classList.toggle('open');
            btn.classList.toggle('open');
          }
        });
      });

      // Module accordions
      document.querySelectorAll('.module-accordion-header').forEach(header => {
        header.addEventListener('click', () => {
          const body = header.nextElementSibling;
          header.classList.toggle('open');
          body.classList.toggle('open');
        });
      });

      // Copy buttons
      document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.dataset.copy;
          const el = document.getElementById(targetId);
          if (el) {
            navigator.clipboard.writeText(el.textContent).then(() => {
              btn.textContent = 'Copied!';
              btn.classList.add('copied');
              setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
            });
          }
        });
      });

      // Gauge animation
      const gaugeFill = document.getElementById('gaugeFill');
      if (gaugeFill) {
        const score = parseInt(gaugeFill.dataset.score);
        const circ = 2 * Math.PI * 70;
        const offset = circ - (score / 100) * circ;
        setTimeout(() => { gaugeFill.style.strokeDashoffset = offset; }, 100);
      }

      // Active nav highlight on scroll
      const sections = document.querySelectorAll('section[id]');
      const navItems = document.querySelectorAll('.nav-item[data-section]');
      const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            navItems.forEach(n => n.classList.remove('active'));
            const active = document.querySelector('.nav-item[data-section="' + entry.target.id + '"]');
            if (active) active.classList.add('active');
          }
        });
      }, { rootMargin: '-30% 0px -60% 0px' });
      sections.forEach(s => observer.observe(s));
    });
    """


def generate_sidebar(data: dict) -> str:
    mods = data["meta"].get("modules_run", [])
    mod_items = "".join(
        f'<a class="nav-item" data-section="module-{m}" href="#module-{m}">'
        f'{html.escape(m.upper())}</a>'
        for m in mods
    )
    return f"""
    <nav class="sidebar">
      <div class="sidebar-logo">
        <div class="tool-name">HAAKAUTH</div>
        <div class="tool-sub">Security Report</div>
      </div>
      <span class="nav-section">Report</span>
      <a class="nav-item" data-section="header" href="#header">Overview</a>
      <a class="nav-item" data-section="summary" href="#summary">Summary</a>
      <a class="nav-item" data-section="gauge" href="#gauge">Risk Score</a>
      <a class="nav-item" data-section="chart" href="#chart">By Module</a>
      <span class="nav-section">Findings</span>
      <a class="nav-item" data-section="findings" href="#findings">All Findings</a>
      <span class="nav-section">Modules</span>
      {mod_items}
      <span class="nav-section">Report</span>
      <a class="nav-item" data-section="methodology" href="#methodology">Methodology</a>
      <div class="sidebar-footer">
        HAAK Cybersecurity<br>© 2026
      </div>
    </nav>
    """


def generate_header(data: dict) -> str:
    meta = data["meta"]
    duration_str = fmt_duration(meta.get("duration_seconds", 0))
    mods_str = html.escape(", ".join(meta.get("modules_run", [])))
    return f"""
    <section id="header">
      <div class="report-header">
        <h1>HAAKAUTH</h1>
        <div class="subtitle">Authentication &amp; Authorization Security Report</div>
        <div class="meta-grid">
          <div class="meta-item">
            <span class="meta-label">Target</span>
            <span class="meta-value accent">{html.escape(meta.get("target", "N/A"))}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Date</span>
            <span class="meta-value">{html.escape(meta.get("date", "N/A"))}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Engagement</span>
            <span class="meta-value">{html.escape(meta.get("engagement", "N/A"))}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Duration</span>
            <span class="meta-value">{duration_str}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Version</span>
            <span class="meta-value">{html.escape(meta.get("version", "1.0.0"))}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Modules</span>
            <span class="meta-value">{mods_str}</span>
          </div>
        </div>
      </div>
    </section>
    """


def generate_summary(data: dict) -> str:
    stats = data["stats"]
    counts = {
        "critical": stats.get("findings_critical", 0),
        "high": stats.get("findings_high", 0),
        "medium": stats.get("findings_medium", 0),
        "low": stats.get("findings_low", 0),
        "info": stats.get("findings_info", 0),
    }

    cards = ""
    for sev, count in counts.items():
        cards += f"""
        <div class="sev-card {sev}">
          <div class="sev-count" data-count="{count}">{count}</div>
          <div class="sev-label">{sev.upper()}</div>
        </div>"""

    risk_lbl, risk_color = overall_risk(stats)
    total_tests = stats.get("total_tests", 0)
    total_reqs = data["meta"].get("total_requests", 0)

    return f"""
    <section id="summary" class="section">
      <div class="section-title">Executive Summary</div>
      <div class="summary-row">{cards}</div>
      <div class="overall-risk-row">
        <div>
          <span class="meta-label" style="display:block;margin-bottom:6px;">Overall Risk Rating</span>
          <span class="risk-badge" style="background:{risk_color}1a;color:{risk_color};border:1px solid {risk_color}40;">
            {risk_lbl}
          </span>
        </div>
        <div class="overall-stats">
          <div class="stat-item">
            <span class="stat-num">{total_tests}</span>
            <span class="stat-lbl">Tests Run</span>
          </div>
          <div class="stat-item">
            <span class="stat-num">{total_reqs}</span>
            <span class="stat-lbl">HTTP Requests</span>
          </div>
          <div class="stat-item">
            <span class="stat-num">{sum(counts.values())}</span>
            <span class="stat-lbl">Total Findings</span>
          </div>
        </div>
      </div>
    </section>
    """


def generate_risk_gauge(data: dict) -> str:
    stats = data["stats"]
    score = calculate_risk_score(stats)
    label, color = risk_label(score)

    circ = 2 * 3.14159 * 70
    initial_offset = circ  # starts at 0, JS animates

    counts = {
        "critical": stats.get("findings_critical", 0),
        "high": stats.get("findings_high", 0),
        "medium": stats.get("findings_medium", 0),
        "low": stats.get("findings_low", 0),
        "info": stats.get("findings_info", 0),
    }
    chips = "".join(
        f'<span class="gauge-chip" style="color:{severity_color(s)};border-color:{severity_color(s)}40;">'
        f'{s.upper()}: -{("30" if s=="critical" else "15" if s=="high" else "8" if s=="medium" else "3" if s=="low" else "1")} pts × {c}'
        f'</span>'
        for s, c in counts.items() if c > 0
    )

    desc = {
        "CRITICAL": "Authentication security is critically compromised. Immediate remediation required — high-severity vulnerabilities expose the system to complete authentication bypass or account takeover.",
        "POOR": "Authentication posture is poor. Multiple high-severity issues detected. Remediation should be prioritized before production release.",
        "FAIR": "Authentication posture is below acceptable thresholds. Medium-severity findings require attention; a follow-up assessment is recommended.",
        "GOOD": "Authentication controls are generally sound with minor gaps. Address low-severity findings as part of normal development cycle.",
        "STRONG": "Authentication implementation meets security best practices. Continue periodic reassessment.",
    }.get(label, "")

    return f"""
    <section id="gauge" class="section">
      <div class="section-title">Auth Security Posture</div>
      <div class="gauge-wrapper">
        <div class="gauge-container">
          <svg class="gauge-svg" viewBox="0 0 180 180">
            <circle class="gauge-track" cx="90" cy="90" r="70"
              stroke-dasharray="{circ:.1f}" stroke-dashoffset="0"/>
            <circle class="gauge-fill" id="gaugeFill" cx="90" cy="90" r="70"
              stroke="{color}"
              stroke-dasharray="{circ:.1f}"
              stroke-dashoffset="{initial_offset:.1f}"
              data-score="{score}"/>
          </svg>
          <div class="gauge-center">
            <div class="gauge-score" style="color:{color}">{score}</div>
            <div class="gauge-score-label">/ 100</div>
          </div>
        </div>
        <div class="gauge-info">
          <h3 style="color:{color}">{label}</h3>
          <p>{desc}</p>
          <div class="gauge-breakdown">
            {chips}
          </div>
        </div>
      </div>
    </section>
    """


def generate_module_chart(data: dict) -> str:
    stats = data["stats"]
    modules_data = stats.get("modules", {})
    if not modules_data:
        return ""

    max_tests = max((v.get("tests", 0) for v in modules_data.values()), default=1)
    if max_tests == 0:
        max_tests = 1

    module_descriptions = {
        "jwt": "JSON Web Token security — algorithm confusion, none bypass, weak secrets, expiry",
        "idor": "Insecure Direct Object Reference — horizontal/vertical privilege escalation, object enumeration",
        "bypass": "Authentication bypass — forced browsing, parameter manipulation, response tampering",
        "session": "Session management — fixation, prediction, timeout, cookie flags",
        "rate": "Rate limiting — brute force protection, lockout policies, OTP throttling",
    }

    rows = ""
    for mod_name, mod_stats in modules_data.items():
        tests = mod_stats.get("tests", 0)
        findings = mod_stats.get("findings", 0)
        bar_pct = (tests / max_tests) * 100
        find_pct = (findings / tests * 100) if tests > 0 else 0

        rows += f"""
        <div class="chart-row">
          <div class="chart-label">{html.escape(mod_name.upper())}</div>
          <div class="chart-bar-track">
            <div class="chart-bar-fill" style="width:{bar_pct:.1f}%">
              <div class="chart-segment" style="flex:{tests - findings};background:rgba(0,200,255,0.25);"></div>
              <div class="chart-segment" style="flex:{findings};background:rgba(255,107,0,0.7);"></div>
            </div>
          </div>
          <div class="chart-meta">{tests} tests &nbsp;|&nbsp; <span style="color:{'var(--high)' if findings > 0 else 'var(--low)'}">
            {findings} found ({find_pct:.0f}%)</span>
          </div>
        </div>"""

    legend = """
    <div style="display:flex;gap:16px;margin-top:16px;font-size:11px;color:var(--text-muted);">
      <span><span style="display:inline-block;width:10px;height:10px;background:rgba(0,200,255,0.25);border-radius:2px;margin-right:4px;"></span>Passed</span>
      <span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,107,0,0.7);border-radius:2px;margin-right:4px;"></span>Findings</span>
    </div>"""

    return f"""
    <section id="chart" class="section">
      <div class="section-title">Findings by Module</div>
      <div class="chart-container">
        {rows}
        {legend}
      </div>
    </section>
    """


def generate_findings(data: dict) -> str:
    findings = sorted(data.get("findings", []), key=lambda f: severity_order(f.get("severity", "info")))

    filter_btns = """
    <div class="filter-bar">
      <button class="filter-btn active" data-filter="all" onclick="setFilter('all')">All</button>
      <button class="filter-btn f-critical" data-filter="critical" onclick="setFilter('critical')">Critical</button>
      <button class="filter-btn f-high" data-filter="high" onclick="setFilter('high')">High</button>
      <button class="filter-btn f-medium" data-filter="medium" onclick="setFilter('medium')">Medium</button>
      <button class="filter-btn f-low" data-filter="low" onclick="setFilter('low')">Low</button>
      <button class="filter-btn f-info" data-filter="info" onclick="setFilter('info')">Info</button>
      <input class="search-box" id="findingSearch" type="text" placeholder="Search findings...">
    </div>
    """

    cards = ""
    for idx, finding in enumerate(findings):
        sev = finding.get("severity", "info").lower()
        title = html.escape(finding.get("title", "Untitled"))
        desc = html.escape(finding.get("description", ""))
        evidence = html.escape(finding.get("evidence", ""))
        module = html.escape(finding.get("module", ""))
        remediation = html.escape(finding.get("remediation", ""))
        cwe = html.escape(finding.get("cwe", ""))
        refs = finding.get("references", [])
        ts = finding.get("timestamp", "")
        if ts:
            try:
                ts = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
            except Exception:
                ts = html.escape(ts)

        sev_color = severity_color(sev)

        # Build request/response block
        req_data = finding.get("request_data", {})
        resp_data = finding.get("response_data", {})
        req_id = f"req_{idx}"
        resp_id = f"resp_{idx}"
        coll_id = f"coll_{idx}"
        ev_id = f"ev_{idx}"

        req_text = ""
        if req_data:
            method = req_data.get("method", "GET")
            url = req_data.get("url", "")
            headers = req_data.get("headers", {})
            body = req_data.get("body", "")
            req_lines = [f"{method} {url}"]
            for hk, hv in headers.items():
                req_lines.append(f"{hk}: {hv}")
            if body:
                req_lines.append("")
                req_lines.append(body)
            req_text = html.escape("\n".join(req_lines))

        resp_text = ""
        status_class = "status-2xx"
        if resp_data:
            sc = resp_data.get("status_code", 200)
            if sc >= 500:
                status_class = "status-5xx"
            elif sc >= 400:
                status_class = "status-4xx"
            resp_headers = resp_data.get("headers", {})
            resp_body = str(resp_data.get("body", ""))[:500]
            resp_lines = [f"HTTP/1.1 {sc}"]
            for hk, hv in resp_headers.items():
                resp_lines.append(f"{hk}: {hv}")
            resp_lines.append("")
            resp_lines.append(resp_body)
            resp_text = html.escape("\n".join(resp_lines))

        req_resp_html = ""
        if req_text or resp_text:
            req_resp_html = f"""
            <button class="collapsible-btn" data-target="{coll_id}">
              <span class="arrow">▶</span> Request / Response
            </button>
            <div class="collapsible-content" id="{coll_id}">
              <div class="req-resp-row">"""
            if req_text:
                req_resp_html += f"""
                <div class="req-resp-col">
                  <div class="req-resp-col-title">Request</div>
                  <div class="req-resp-block" id="{req_id}"><span>{req_text}</span>
                    <button class="copy-btn" data-copy="{req_id}">Copy</button>
                  </div>
                </div>"""
            if resp_text:
                req_resp_html += f"""
                <div class="req-resp-col">
                  <div class="req-resp-col-title">Response</div>
                  <div class="req-resp-block" id="{resp_id}"><span class="{status_class}">{resp_text}</span>
                    <button class="copy-btn" data-copy="{resp_id}">Copy</button>
                  </div>
                </div>"""
            req_resp_html += """
              </div>
            </div>"""

        cwe_html = ""
        if cwe:
            cwe_num = cwe.replace("CWE-", "")
            cwe_html = f'<a class="cwe-link" href="https://cwe.mitre.org/data/definitions/{html.escape(cwe_num)}.html" target="_blank">{cwe}</a>'

        ref_html = ""
        for ref in refs[:3]:
            ref_html += f'<a class="cwe-link" href="{html.escape(ref)}" target="_blank" style="border-color:rgba(0,200,255,0.2);color:var(--accent);">{html.escape(ref[:50])}...</a>'

        ts_html = f'<span class="finding-ts">{ts}</span>' if ts else ""

        cards += f"""
        <div class="finding-card sev-{sev}" data-severity="{sev}">
          <div class="finding-card-header">
            <span class="badge" style="background:{sev_color}1a;color:{sev_color};border:1px solid {sev_color}40;">{sev.upper()}</span>
            <span class="badge badge-module">{module.upper()}</span>
            <span class="finding-title">{title}</span>
            {ts_html}
          </div>
          <div class="finding-desc">{desc}</div>
          <div class="evidence-label">Evidence</div>
          <div class="evidence-block" id="{ev_id}">{evidence}
            <button class="copy-btn" data-copy="{ev_id}">Copy</button>
          </div>
          {req_resp_html}
          <div class="remediation-block">
            <div class="remediation-label">Remediation</div>
            <div class="remediation-text">{remediation}</div>
          </div>
          <div class="finding-footer">
            {cwe_html}
            {ref_html}
          </div>
        </div>"""

    if not cards:
        cards = '<div style="color:var(--text-muted);text-align:center;padding:40px;">No findings recorded.</div>'

    return f"""
    <section id="findings" class="section">
      <div class="section-title">Findings ({len(findings)})</div>
      {filter_btns}
      {cards}
    </section>
    """


def generate_module_details(data: dict) -> str:
    stats = data["stats"]
    modules_data = stats.get("modules", {})
    findings = data.get("findings", [])
    meta = data["meta"]
    mods_run = meta.get("modules_run", list(modules_data.keys()))

    module_descriptions = {
        "jwt": ("JWT Security", "Tests for algorithm confusion attacks (HS256/RS256), 'none' algorithm acceptance, weak HMAC secrets via dictionary attack, missing signature validation, expiry bypass, and claim manipulation."),
        "idor": ("IDOR / Broken Object Level Auth", "Tests for insecure direct object references by manipulating resource IDs, UUIDs, and sequential identifiers. Validates horizontal and vertical privilege separation."),
        "bypass": ("Authentication Bypass", "Tests for forced browsing to authenticated endpoints, parameter manipulation to skip auth checks, response tampering (status code modification), and HTTP verb abuse."),
        "session": ("Session Management", "Tests for session fixation, predictable session tokens, insufficient entropy, missing Secure/HttpOnly/SameSite cookie flags, and improper session invalidation on logout."),
        "rate": ("Rate Limiting", "Tests for missing brute-force protections on login, registration, OTP, and password reset endpoints. Validates lockout thresholds and IP-based throttling."),
    }

    sections = ""
    for mod_name in mods_run:
        mod_stats = modules_data.get(mod_name, {})
        tests = mod_stats.get("tests", 0)
        mod_findings = [f for f in findings if f.get("module", "").lower() == mod_name.lower()]
        f_count = len(mod_findings)
        default_desc = ("Security tests for this module.", "")
        mod_title, mod_desc = module_descriptions.get(mod_name, (mod_name.upper(), default_desc[1]))

        finding_list = ""
        for mf in mod_findings:
            sev = mf.get("severity", "info")
            finding_list += f"""
            <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">
              <span style="width:8px;height:8px;border-radius:50%;background:{severity_color(sev)};flex-shrink:0;"></span>
              <span style="font-size:12px;color:var(--text);">{html.escape(mf.get('title',''))}</span>
              <span style="font-size:10px;color:{severity_color(sev)};margin-left:auto;">{sev.upper()}</span>
            </div>"""

        sections += f"""
        <div class="module-accordion" id="module-{html.escape(mod_name)}">
          <div class="module-accordion-header">
            <span class="badge badge-module">{html.escape(mod_name.upper())}</span>
            <span class="mod-name">{html.escape(mod_title)}</span>
            <span class="mod-stats">{tests} tests · <span style="color:{'var(--high)' if f_count>0 else 'var(--low)'};">{f_count} findings</span></span>
            <span class="mod-arrow">▶</span>
          </div>
          <div class="module-accordion-body">
            <p class="module-desc">{html.escape(mod_desc)}</p>
            {'<div style="margin-top:8px;">' + finding_list + '</div>' if finding_list else '<p style="font-size:12px;color:var(--text-muted);margin-top:8px;">No findings for this module.</p>'}
          </div>
        </div>"""

    return f"""
    <section id="modules" class="section">
      <div class="section-title">Module Details</div>
      {sections}
    </section>
    """


def generate_methodology(data: dict) -> str:
    meta = data["meta"]
    stats = data["stats"]
    modules_data = stats.get("modules", {})

    cards = [
        ("Tool", meta.get("tool", "HaakAuth"), ""),
        ("Version", meta.get("version", "1.0.0"), ""),
        ("Total Tests", str(stats.get("total_tests", 0)), "automated checks"),
        ("HTTP Requests", str(meta.get("total_requests", 0)), "during assessment"),
        ("Duration", fmt_duration(meta.get("duration_seconds", 0)), "wall-clock time"),
        ("Modules", str(len(meta.get("modules_run", []))), "security domains"),
    ]

    cards_html = ""
    for label, value, sub in cards:
        cards_html += f"""
        <div class="method-card">
          <div class="method-card-label">{html.escape(label)}</div>
          <div class="method-card-value">{html.escape(value)}</div>
          {'<div class="method-card-sub">' + html.escape(sub) + '</div>' if sub else ''}
        </div>"""

    mod_rows = ""
    for mod_name, mod_stats in modules_data.items():
        mod_rows += f"""
        <tr>
          <td style="padding:8px 12px;font-weight:600;color:var(--accent);">{html.escape(mod_name.upper())}</td>
          <td style="padding:8px 12px;color:var(--text-muted);">{mod_stats.get('tests', 0)}</td>
          <td style="padding:8px 12px;color:var(--text-muted);">{mod_stats.get('findings', 0)}</td>
        </tr>"""

    return f"""
    <section id="methodology" class="section">
      <div class="section-title">Methodology</div>
      <div class="method-grid">{cards_html}</div>
      <div style="margin-top:24px;background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="background:rgba(255,255,255,0.03);">
              <th style="padding:10px 12px;text-align:left;font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);">Module</th>
              <th style="padding:10px 12px;text-align:left;font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);">Tests Run</th>
              <th style="padding:10px 12px;text-align:left;font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);">Findings</th>
            </tr>
          </thead>
          <tbody>{mod_rows}</tbody>
        </table>
      </div>
    </section>
    """


def generate_footer(data: dict) -> str:
    meta = data["meta"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""
    <footer class="report-footer">
      <div class="footer-brand">HAAK Cybersecurity Consulting</div>
      <div class="footer-meta">
        Generated by {html.escape(meta.get("tool", "HaakAuth"))} v{html.escape(meta.get("version", "1.0.0"))}<br>
        Adrian Martinez — me@adrianmartinez.lat<br>
        Report generated: {now}
      </div>
      <div class="footer-disclaimer">
        This report is confidential and intended solely for the authorized recipient.
        All testing was performed with explicit written authorization.
        Unauthorized distribution or use of this report is strictly prohibited.
        HAAK Cybersecurity Consulting assumes no liability for actions taken based on this report.
      </div>
    </footer>
    """


def generate_report(data: dict) -> str:
    meta = data["meta"]
    title = f"HaakAuth Report — {meta.get('target', 'Assessment')}"

    css = generate_css()
    js = generate_js()
    sidebar = generate_sidebar(data)
    header = generate_header(data)
    summary = generate_summary(data)
    gauge = generate_risk_gauge(data)
    chart = generate_module_chart(data)
    findings = generate_findings(data)
    modules = generate_module_details(data)
    methodology = generate_methodology(data)
    footer = generate_footer(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <style>{css}</style>
</head>
<body>
  {sidebar}
  <div class="top-bar"></div>
  <main class="main">
    {header}
    {summary}
    {gauge}
    {chart}
    {findings}
    {modules}
    {methodology}
    {footer}
  </main>
  <script>{js}</script>
</body>
</html>"""


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 haakauth_report.py scan_results.json output_report.html")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not Path(input_path).exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    print(f"[*] Loading scan results from {input_path}")
    data = load_data(input_path)

    print("[*] Generating report...")
    report_html = generate_report(data)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_html, encoding="utf-8")

    size_kb = out.stat().st_size / 1024
    findings_count = len(data.get("findings", []))
    score = calculate_risk_score(data.get("stats", {}))
    label, _ = risk_label(score)

    print(f"[+] Report generated: {output_path}")
    print(f"    Size:     {size_kb:.1f} KB")
    print(f"    Findings: {findings_count}")
    print(f"    Score:    {score}/100 ({label})")
    print(f"    Target:   {data['meta'].get('target', 'N/A')}")


if __name__ == "__main__":
    main()
