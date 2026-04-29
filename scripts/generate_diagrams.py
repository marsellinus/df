#!/usr/bin/env python3
"""
scripts/generate_diagrams.py
Generate semua diagram dan rumus untuk README dan laporan teknis.
Output: docs/images/*.png
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import numpy as np
from pathlib import Path

OUT = Path(__file__).parent.parent / 'docs' / 'images'
OUT.mkdir(parents=True, exist_ok=True)

DARK   = '#0a0f1e'
SURF   = '#111827'
CARD   = '#1a2235'
BORDER = '#1f2d45'
ACCENT = '#3b82f6'
RED    = '#ef4444'
ORANGE = '#f97316'
YELLOW = '#eab308'
GREEN  = '#22c55e'
PURPLE = '#a855f7'
TEXT   = '#e2e8f0'
MUTED  = '#64748b'


def savefig(name):
    path = OUT / name
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=DARK, edgecolor='none')
    plt.close()
    print(f'  ✓ {path}')


# ─────────────────────────────────────────────────────────────────────────────
# 1. Pipeline Architecture Diagram
# ─────────────────────────────────────────────────────────────────────────────
def fig_pipeline():
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)
    ax.set_xlim(0, 12); ax.set_ylim(0, 7)
    ax.axis('off')

    ax.text(6, 6.6, 'Forensic Pipeline Architecture',
            ha='center', va='center', fontsize=14, fontweight='bold',
            color=TEXT, fontfamily='monospace')

    # Data sources (top row)
    sources = [
        (1.5, 5.5, 'Nextcloud\nnginx JSON', ACCENT),
        (4.0, 5.5, 'Nextcloud\nadmin_audit', ACCENT),
        (6.5, 5.5, 'CERT file.csv\n(Insider Threat)', PURPLE),
        (9.0, 5.5, 'CERT logon.csv\ndevice.csv', PURPLE),
    ]
    for x, y, label, color in sources:
        box = FancyBboxPatch((x-1.1, y-0.35), 2.2, 0.7,
                             boxstyle='round,pad=0.05',
                             facecolor=color+'22', edgecolor=color, linewidth=1.2)
        ax.add_patch(box)
        ax.text(x, y, label, ha='center', va='center',
                fontsize=7.5, color=color, fontfamily='monospace')

    # Pipeline stages
    stages = [
        (5.5, 4.4, 'log_parser.py', 'Normalisasi → schema standar\n(7 format didukung)', ACCENT),
        (5.5, 3.5, 'metadata_correlator.py', 'User profile · IP profile · cross-source', GREEN),
        (5.5, 2.6, 'anomaly_detector.py', '5 rule-based detectors', ORANGE),
        (5.5, 1.7, 'ML Ensemble', 'Random Forest · Gradient Boosting · Logistic Regression', YELLOW),
        (5.5, 0.8, 'risk_engine.py  →  timeline_reconstructor.py', 'Risk Score 0–100 · WHO/WHEN/WHAT/HOW MUCH', RED),
    ]
    for x, y, title, sub, color in stages:
        box = FancyBboxPatch((x-4.5, y-0.32), 9.0, 0.64,
                             boxstyle='round,pad=0.05',
                             facecolor=color+'18', edgecolor=color, linewidth=1.2)
        ax.add_patch(box)
        ax.text(x-2.2, y, title, ha='left', va='center',
                fontsize=8.5, fontweight='bold', color=color, fontfamily='monospace')
        ax.text(x+0.5, y, sub, ha='left', va='center',
                fontsize=7.5, color=MUTED, fontfamily='monospace')

    # Arrows from sources to parser
    for x, _, _, _ in sources:
        ax.annotate('', xy=(5.5, 4.76), xytext=(x, 5.17),
                    arrowprops=dict(arrowstyle='->', color=MUTED, lw=1.2))

    # Arrows between stages
    for y_from, y_to in [(4.08, 3.82), (3.18, 2.92), (2.28, 2.02), (1.38, 1.12)]:
        ax.annotate('', xy=(5.5, y_to), xytext=(5.5, y_from),
                    arrowprops=dict(arrowstyle='->', color=MUTED, lw=1.5))

    savefig('pipeline_architecture.png')


# ─────────────────────────────────────────────────────────────────────────────
# 2. Risk Score Formula
# ─────────────────────────────────────────────────────────────────────────────
def fig_risk_formula():
    fig, ax = plt.subplots(figsize=(11, 5.5))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)
    ax.axis('off')

    ax.text(0.5, 0.96, 'Exfiltration Risk Score Formula',
            transform=ax.transAxes, ha='center', va='top',
            fontsize=13, fontweight='bold', color=TEXT)

    # Main formula
    ax.text(0.5, 0.80,
            r'$R_{user} = \min\!\left(100,\; \sum_{i} w_i \cdot s_i \cdot m_i\right)$',
            transform=ax.transAxes, ha='center', va='center',
            fontsize=16, color=RED,
            bbox=dict(boxstyle='round,pad=0.4', facecolor=RED+'18', edgecolor=RED, linewidth=1.5))

    # Session risk
    ax.text(0.5, 0.63,
            r'$R_{session} = \min\!\left(100,\; \max_u(R_u) \times 0.6 + \bar{R}_u \times 0.4\right)$',
            transform=ax.transAxes, ha='center', va='center',
            fontsize=13, color=ORANGE,
            bbox=dict(boxstyle='round,pad=0.3', facecolor=ORANGE+'18', edgecolor=ORANGE, linewidth=1.2))

    # Variable table
    rows = [
        (r'$w_i$',  'Bobot sinyal anomali',          'bulk_download=40, sensitive_file=25, off_hours=15, multi_ip=15, rapid=5'),
        (r'$s_i$',  'Skor sinyal (0–1)',              'Proporsi event anomali terhadap total event user'),
        (r'$m_i$',  'Multiplier severity',            'CRITICAL=1.5 · HIGH=1.2 · MEDIUM=1.0 · LOW=0.7'),
        (r'$R_u$',  'Risk score per user (0–100)',    'SAFE<20 · LOW<40 · MEDIUM<60 · HIGH<80 · CRITICAL≥80'),
    ]
    y = 0.46
    for sym, name, desc in rows:
        ax.text(0.04, y, sym,       transform=ax.transAxes, ha='left', va='center', fontsize=11, color=YELLOW)
        ax.text(0.14, y, name,      transform=ax.transAxes, ha='left', va='center', fontsize=9,  color=TEXT)
        ax.text(0.38, y, desc,      transform=ax.transAxes, ha='left', va='center', fontsize=8,  color=MUTED)
        from matplotlib.lines import Line2D
        line = Line2D([0.03, 0.97], [y-0.055, y-0.055],
                      transform=ax.transAxes, color=BORDER, linewidth=0.5)
        ax.add_line(line)
        y -= 0.11

    # Risk bands
    bands = [('SAFE', GREEN, '<20'), ('LOW', ACCENT, '20–39'),
             ('MEDIUM', YELLOW, '40–59'), ('HIGH', ORANGE, '60–79'), ('CRITICAL', RED, '≥80')]
    bx = 0.05
    for label, color, rng in bands:
        ax.text(bx, 0.04, f'{label}\n{rng}', transform=ax.transAxes,
                ha='left', va='bottom', fontsize=8, fontweight='bold', color=color,
                bbox=dict(boxstyle='round,pad=0.3', facecolor=color+'22', edgecolor=color, linewidth=1))
        bx += 0.19

    savefig('risk_score_formula.png')


# ─────────────────────────────────────────────────────────────────────────────
# 3. ML Ensemble Architecture
# ─────────────────────────────────────────────────────────────────────────────
def fig_ml_ensemble():
    fig, ax = plt.subplots(figsize=(11, 5))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)
    ax.set_xlim(0, 11); ax.set_ylim(0, 5)
    ax.axis('off')

    ax.text(5.5, 4.7, 'ML Ensemble Anomaly Detection',
            ha='center', fontsize=13, fontweight='bold', color=TEXT)

    # Input features
    feats = ['hour_of_day', 'is_business_hours', 'bytes_mb',
             'is_large_transfer', 'is_sensitive_file', 'ip_first_octet',
             'user_id', 'action_encoded', 'object_name_length',
             'day_of_week', 'object_name_length']
    feat_box = FancyBboxPatch((0.1, 1.2), 2.0, 2.6,
                              boxstyle='round,pad=0.1',
                              facecolor=ACCENT+'18', edgecolor=ACCENT, linewidth=1.2)
    ax.add_patch(feat_box)
    ax.text(1.1, 3.95, 'Input Features\n(11 features)', ha='center',
            fontsize=8.5, fontweight='bold', color=ACCENT)
    for i, f in enumerate(feats[:9]):
        ax.text(1.1, 3.55 - i*0.26, f'• {f}', ha='center',
                fontsize=6.5, color=MUTED)

    # Models
    models = [
        (4.2, 3.5, 'Random\nForest', GREEN,  'n=100 trees\nmax_depth=15'),
        (4.2, 2.5, 'Gradient\nBoosting', YELLOW, 'n=100\nlr=0.1'),
        (4.2, 1.5, 'Logistic\nRegression', PURPLE, 'max_iter=1000'),
    ]
    for x, y, name, color, params in models:
        box = FancyBboxPatch((x-0.85, y-0.38), 1.7, 0.76,
                             boxstyle='round,pad=0.05',
                             facecolor=color+'22', edgecolor=color, linewidth=1.2)
        ax.add_patch(box)
        ax.text(x-0.1, y+0.1, name, ha='center', va='center',
                fontsize=8, fontweight='bold', color=color)
        ax.text(x-0.1, y-0.18, params, ha='center', va='center',
                fontsize=6.5, color=MUTED)
        # Arrow from features
        ax.annotate('', xy=(x-0.85, y), xytext=(2.1, y),
                    arrowprops=dict(arrowstyle='->', color=MUTED, lw=1))

    # Probability outputs
    for x, y, _, color, _ in models:
        ax.text(5.35, y, f'P(anomaly)', ha='left', va='center',
                fontsize=7, color=color)
        ax.annotate('', xy=(5.3, y), xytext=(x+0.85, y),
                    arrowprops=dict(arrowstyle='->', color=color, lw=1))

    # Ensemble aggregation
    agg_box = FancyBboxPatch((6.5, 1.9), 2.0, 1.2,
                             boxstyle='round,pad=0.1',
                             facecolor=ORANGE+'22', edgecolor=ORANGE, linewidth=1.5)
    ax.add_patch(agg_box)
    ax.text(7.5, 2.8, 'Ensemble\nAggregation', ha='center', va='center',
            fontsize=8.5, fontweight='bold', color=ORANGE)
    ax.text(7.5, 2.35,
            r'$\bar{P} = \frac{1}{3}\sum_{k=1}^{3} P_k$',
            ha='center', va='center', fontsize=9, color=TEXT)

    for y in [3.5, 2.5, 1.5]:
        ax.annotate('', xy=(6.5, 2.5), xytext=(5.9, y),
                    arrowprops=dict(arrowstyle='->', color=MUTED, lw=1))

    # Decision
    dec_box = FancyBboxPatch((9.0, 2.0), 1.8, 1.0,
                             boxstyle='round,pad=0.1',
                             facecolor=RED+'22', edgecolor=RED, linewidth=1.5)
    ax.add_patch(dec_box)
    ax.text(9.9, 2.7, 'Decision', ha='center', fontsize=8.5,
            fontweight='bold', color=RED)
    ax.text(9.9, 2.35, r'$\bar{P} \geq 0.6$', ha='center',
            fontsize=9, color=TEXT)
    ax.text(9.9, 2.1, '→ ML_ANOMALY', ha='center', fontsize=7, color=RED)
    ax.annotate('', xy=(9.0, 2.5), xytext=(8.5, 2.5),
                arrowprops=dict(arrowstyle='->', color=ORANGE, lw=1.5))

    savefig('ml_ensemble.png')


# ─────────────────────────────────────────────────────────────────────────────
# 4. ML Model Performance Chart
# ─────────────────────────────────────────────────────────────────────────────
def fig_ml_performance():
    models  = ['Random Forest', 'Gradient Boosting', 'Logistic Regression']
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']
    values  = [
        [0.9947, 1.0000, 0.9500, 0.9744, 0.9997],
        [0.9894, 1.0000, 0.9000, 0.9474, 1.0000],
        [0.9894, 1.0000, 0.9000, 0.9474, 0.9964],
    ]
    colors = [GREEN, YELLOW, PURPLE]

    x = np.arange(len(metrics))
    width = 0.25
    fig, ax = plt.subplots(figsize=(11, 5))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)

    for i, (model, vals, color) in enumerate(zip(models, values, colors)):
        bars = ax.bar(x + i*width, [v*100 for v in vals], width,
                      label=model, color=color, alpha=0.85, zorder=3)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    f'{val*100:.1f}', ha='center', va='bottom',
                    fontsize=6.5, color=TEXT)

    ax.set_ylim(85, 103)
    ax.set_xticks(x + width)
    ax.set_xticklabels(metrics, color=TEXT, fontsize=9)
    ax.set_ylabel('Score (%)', color=MUTED, fontsize=9)
    ax.set_title('ML Model Performance — Cross-Dataset Evaluation',
                 color=TEXT, fontsize=12, fontweight='bold', pad=12)
    ax.tick_params(colors=MUTED)
    ax.spines[:].set_color(BORDER)
    ax.yaxis.grid(True, color=BORDER, linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)
    legend = ax.legend(facecolor=CARD, edgecolor=BORDER,
                       labelcolor=TEXT, fontsize=8.5)
    ax.axhline(y=95, color=MUTED, linewidth=0.8, linestyle='--', alpha=0.5)
    ax.text(4.7, 95.3, '95% threshold', color=MUTED, fontsize=7.5)

    savefig('ml_performance.png')


# ─────────────────────────────────────────────────────────────────────────────
# 5. Attack Phase Timeline
# ─────────────────────────────────────────────────────────────────────────────
def fig_attack_phases():
    phases = [
        ('RECONNAISSANCE',      0.5,  1.5, MUTED,   'Failed logins\nPROPFIND enum'),
        ('TARGET ACCESS',       1.5,  3.0, ORANGE,  'Sensitive file\nidentification'),
        ('DATA STAGING',        3.0,  4.5, YELLOW,  'File copy\npreparation'),
        ('EXFILTRATION',        4.5,  7.5, RED,     'Bulk GET / USB\nCopy to external'),
        ('STEALTH OPERATION',   7.5,  9.5, PURPLE,  'Off-hours access\nAnti-forensics'),
        ('EVIDENCE DESTRUCTION',9.5, 10.5, '#f43f5e','DELETE ops\nLog clearing'),
    ]

    fig, ax = plt.subplots(figsize=(13, 3.5))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)
    ax.set_xlim(0, 11); ax.set_ylim(0, 3)
    ax.axis('off')

    ax.text(5.5, 2.85, 'Attack Phase Timeline — Exfiltration Kill Chain',
            ha='center', fontsize=12, fontweight='bold', color=TEXT)

    for name, x0, x1, color, desc in phases:
        w = x1 - x0
        box = FancyBboxPatch((x0+0.05, 1.3), w-0.1, 0.9,
                             boxstyle='round,pad=0.05',
                             facecolor=color+'33', edgecolor=color, linewidth=1.5)
        ax.add_patch(box)
        ax.text((x0+x1)/2, 1.95, name, ha='center', va='center',
                fontsize=6.5, fontweight='bold', color=color)
        ax.text((x0+x1)/2, 1.5, desc, ha='center', va='center',
                fontsize=5.8, color=MUTED)
        # Arrow connector
        if x1 < 10.5:
            ax.annotate('', xy=(x1+0.05, 1.75), xytext=(x1-0.05, 1.75),
                        arrowprops=dict(arrowstyle='->', color=MUTED, lw=1))

    # Timeline axis
    ax.axhline(y=1.25, xmin=0.02, xmax=0.98, color=BORDER, linewidth=1)
    for x, label in [(0.5,'T+0'), (2.25,'T+1h'), (3.75,'T+3h'),
                     (6.0,'T+6h'), (8.5,'T+12h'), (10.0,'T+24h')]:
        ax.plot(x, 1.25, 'o', color=MUTED, markersize=4)
        ax.text(x, 1.05, label, ha='center', fontsize=6.5, color=MUTED)

    savefig('attack_phases.png')


# ─────────────────────────────────────────────────────────────────────────────
# 6. Cross-Source Correlation Diagram
# ─────────────────────────────────────────────────────────────────────────────
def fig_cross_source():
    fig, ax = plt.subplots(figsize=(10, 4.5))
    fig.patch.set_facecolor(DARK)
    ax.set_facecolor(DARK)
    ax.set_xlim(0, 10); ax.set_ylim(0, 4.5)
    ax.axis('off')

    ax.text(5, 4.25, 'Cross-Source Metadata Correlation',
            ha='center', fontsize=12, fontweight='bold', color=TEXT)

    # CERT box
    cert_box = FancyBboxPatch((0.2, 0.5), 2.8, 3.0,
                              boxstyle='round,pad=0.1',
                              facecolor=PURPLE+'18', edgecolor=PURPLE, linewidth=1.5)
    ax.add_patch(cert_box)
    ax.text(1.6, 3.3, 'CERT Insider Threat', ha='center',
            fontsize=9, fontweight='bold', color=PURPLE)
    for i, line in enumerate(['• file.csv (file access)', '• logon.csv (auth events)',
                               '• device.csv (USB events)', '• 319 records', '• 4 users (TGT-*)' ]):
        ax.text(1.6, 2.9 - i*0.42, line, ha='center', fontsize=7.5, color=MUTED)

    # Nextcloud box
    nc_box = FancyBboxPatch((7.0, 0.5), 2.8, 3.0,
                            boxstyle='round,pad=0.1',
                            facecolor=ACCENT+'18', edgecolor=ACCENT, linewidth=1.5)
    ax.add_patch(nc_box)
    ax.text(8.4, 3.3, 'Nextcloud Logs', ha='center',
            fontsize=9, fontweight='bold', color=ACCENT)
    for i, line in enumerate(['• nginx JSON (HTTP access)', '• admin_audit (file ops)',
                               '• Real attack traffic', '• 126 records', '• 3 users (alice, admin)']):
        ax.text(8.4, 2.9 - i*0.42, line, ha='center', fontsize=7.5, color=MUTED)

    # Correlation engine center
    corr_box = FancyBboxPatch((3.6, 1.3), 2.8, 1.4,
                              boxstyle='round,pad=0.1',
                              facecolor=GREEN+'18', edgecolor=GREEN, linewidth=1.8)
    ax.add_patch(corr_box)
    ax.text(5.0, 2.35, 'Correlation Engine', ha='center',
            fontsize=9, fontweight='bold', color=GREEN)
    ax.text(5.0, 1.95, 'Normalize → Merge → Profile', ha='center',
            fontsize=7.5, color=MUTED)
    ax.text(5.0, 1.6, 'cross_source_summary', ha='center',
            fontsize=7, color=GREEN, style='italic')

    # Arrows
    ax.annotate('', xy=(3.6, 2.0), xytext=(3.0, 2.0),
                arrowprops=dict(arrowstyle='->', color=PURPLE, lw=1.5))
    ax.annotate('', xy=(7.0, 2.0), xytext=(6.4, 2.0),
                arrowprops=dict(arrowstyle='->', color=ACCENT, lw=1.5))

    # Output
    ax.text(5.0, 0.85, '→  WHO: CERT-InsiderThreat [TGT-ACM2278, ...]  |  Nextcloud [alice, admin]',
            ha='center', fontsize=7.5, color=TEXT,
            bbox=dict(boxstyle='round,pad=0.3', facecolor=CARD, edgecolor=BORDER))

    savefig('cross_source_correlation.png')


if __name__ == '__main__':
    print('Generating diagrams...')
    fig_pipeline()
    fig_risk_formula()
    fig_ml_ensemble()
    fig_ml_performance()
    fig_attack_phases()
    fig_cross_source()
    print(f'\nAll diagrams saved to docs/images/')
