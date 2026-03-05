#!/usr/bin/env python3
import json
import os
import sys
from jinja2 import Template

# Constants
REPORT_DIR = os.getenv("REPORT_DIR", "/scanner/reports")
HTML_OUT = os.path.join(REPORT_DIR, "full_report.html")

# ==================== UNIVERSAL PARSER ====================

def parse_sarif(file_path):
    """Parsing SARIF (Semgrep, Gitleaks, Gosec, Hadolint)"""
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return []

    try:
        with open(file_path, encoding='utf-8') as f:
            data = json.load(f)

        findings = []
        for run in data.get('runs', []):
            for result in run.get('results', []):
                level = result.get('level', 'warning').lower()
                
                props = result.get('properties', {})

                severity_raw = props.get('severity', props.get('security-severity', '')).lower()

                if severity_raw in ['critical', 'high', 'medium', 'low']:
                    final_severity = severity_raw
                elif level == 'error':
                    final_severity = 'high'
                elif level == 'warning':
                    final_severity = 'medium'
                elif level == 'note':
                    final_severity = 'low'
                else:
                    final_severity = 'info'

                message = result.get('message', {}).get('text', 'No message')
                rule = result.get('ruleId', 'unknown')
                
                locations = result.get('locations', [])
                uri = "N/A"
                line = ""

                if locations:
                    phys_loc = locations[0].get('physicalLocation', {})
                    art_loc = phys_loc.get('artifactLocation', {})
                    uri = art_loc.get('uri', 'N/A')
                    region = phys_loc.get('region', {})
                    line = region.get('startLine', '')

                findings.append({
                    'title': f"{rule}: {message[:70]}...",
                    'description': message,
                    'severity': final_severity,
                    'file': uri.replace('file://', ''),
                    'line': str(line)
                })
        return findings
    except Exception as e:
        print(f"⚠️ Error parsing SARIF {file_path}: {e}")
        return []

def parse_json(file_path, scanner_name):
    """Parsing JSON (Bandit, Nodejsscan, Trivy)"""
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return []

    try:
        with open(file_path, encoding='utf-8') as f:
            data = json.load(f)
        
        findings = []

        if scanner_name == "semgrep":
            for result in data.get('results', []):
                extra = result.get('extra', {})
                sev = extra.get('severity', 'medium').lower()
                
                findings.append({
                    'title': result.get('check_id', 'Semgrep finding'),
                    'description': extra.get('message', 'No description'),
                    'severity': sev,
                    'file': result.get('path', 'N/A'),
                    'line': str(result.get('start', {}).get('line', ''))
                })

        if scanner_name == "gosec":
            for issue in data.get('Issues', []):
                findings.append({
                    'title': f"{issue.get('rule_id')}: {issue.get('details')[:70]}",
                    'description': issue.get('details'),
                    'severity': issue.get('severity', 'medium').lower(),
                    'file': issue.get('file', 'N/A'),
                    'line': str(issue.get('line', ''))
                })
            return findings
        
        if scanner_name == "trivy":
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    findings.append({
                        'title': f"{vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}",
                        'description': vuln.get('Description', 'No description')[:200],
                        'severity': vuln.get('Severity', 'medium').lower(),
                        'file': result.get('Target', 'N/A'),
                        'line': vuln.get('InstalledVersion', '')
                    })
        
        elif scanner_name == "bandit":
            for issue in data.get('results', []):
                findings.append({
                    'title': issue.get('issue_text', 'Security issue')[:70],
                    'description': f"Test ID: {issue.get('test_id')} | {issue.get('issue_text')}",
                    'severity': issue.get('issue_severity', 'medium').lower(),
                    'file': issue.get('filename', 'N/A'),
                    'line': str(issue.get('line_number', ''))
                })
        
        elif scanner_name == "nodejsscan":
            if not isinstance(data, dict): return []
            
            for cat, issues in data.get("sec_issues", {}).items():
                for issue in issues:
                    findings.append({
                        'title': issue.get("title", "NodeJS issue"),
                        'description': issue.get("description", ""),
                        'severity': 'high',
                        'file': issue.get("filename", "N/A"),
                        'line': str(issue.get("line", ""))
                    })

            for cat, headers in data.get("missing_sec_header", {}).items():
                for head in headers:
                    findings.append({
                        'title': head.get("title", "Missing Header"),
                        'description': head.get("description", ""),
                        'severity': 'medium',
                        'file': "Configuration",
                        'line': ""
                    })
        return findings
    except Exception as e:
        print(f"⚠️ Error parsing JSON {file_path}: {e}")
        return []

# ==================== MAIN LOOP ====================

SCANNERS_CONFIG = [
    {"id": "semgrep", "name": "Semgrep", "file": "semgrep.sarif", "parser": parse_sarif},
    {"id": "bandit", "name": "Bandit", "file": "bandit.json", "parser": lambda f: parse_json(f, "bandit")},
    {"id": "nodejsscan", "name": "Nodejsscan", "file": "nodejsscan.sarif", "parser": parse_sarif},
    {"id": "gitleaks", "name": "Gitleaks", "file": "gitleaks.sarif", "parser": parse_sarif},
    {"id": "gosec", "name": "Gosec", "file": "gosec.json", "parser": lambda f: parse_json(f, "gosec")},
    {"id": "hadolint", "name": "Hadolint", "file": "hadolint.sarif", "parser": parse_sarif},
    {"id": "trivy", "name": "Trivy", "file": "trivy.json", "parser": lambda f: parse_json(f, "trivy")},
]

severity_map = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4
}

def render_html(all_scanners, summary, all_findings_list):
    """Function to generate the final HTML file"""
    with open(HTML_OUT, "w", encoding="utf-8") as f:
        f.write(Template(TEMPLATE).render(
            scanners=all_scanners, 
            total=len(all_findings_list),
            summary=summary
        ))
    print(f"✅ Report generated: {HTML_OUT} (Total issues: {len(all_findings_list)})")

def main():
    all_scanners = []
    all_findings_list = [] 
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    selected_env = os.getenv("TOOL", os.getenv("TOOLS", "all"))
    if selected_env == "all":
        selected_tools = [s['id'] for s in SCANNERS_CONFIG]
    else:
        selected_tools = [t.strip() for t in selected_env.split(',')]

    for s in SCANNERS_CONFIG:
        if s['id'] not in selected_tools:
            continue

        path = os.path.join(REPORT_DIR, s['file'])
        if not os.path.exists(path):
            print(f"⚠️  Report file for {s['name']} not found at {path}")
            continue
        
        findings = s['parser'](path)
        
        findings.sort(key=lambda x: (severity_map.get(x['severity'].lower(), 99), x.get('title', '')))

        processed_findings = []
        for f in findings:
            raw_sev = str(f.get('severity', 'info')).lower().strip()
            
            if raw_sev in ["error", "critical", "fatal"]: clean_sev = "critical"
            elif raw_sev in ["high"]: clean_sev = "high"
            elif raw_sev in ["medium", "warn", "warning"]: clean_sev = "medium"
            elif raw_sev in ["low", "note"]: clean_sev = "low"
            else: clean_sev = "info"

            f['severity'] = clean_sev
            summary[clean_sev] += 1
            all_findings_list.append(f)
            processed_findings.append(f)

        all_scanners.append({
            "id": s["id"],
            "name": s["name"],
            "findings": processed_findings
        })

# --- QUALITY GATE (console output for entrypoint.sh) ---
    high_risk = summary.get("critical", 0) + summary.get("high", 0)
    medium_risk = summary.get("medium", 0)

    if high_risk > 0 or medium_risk > 5:
        print(f"QUALITY_GATE_STATUS=FAILED (High: {high_risk}, Medium: {medium_risk})")
    else:
        print("QUALITY_GATE_STATUS=PASSED")

# --- WRITE TO FILE (use your TEMPLATE below) ---
    try:
        with open(HTML_OUT, "w", encoding="utf-8") as f:
            f.write(Template(TEMPLATE).render(
                scanners=all_scanners, 
                total=len(all_findings_list),
                summary=summary
            ))
        print(f"✅ Report generated: {HTML_OUT} (Total issues: {len(all_findings_list)})")
    except Exception as e:
        print(f"❌ Error generating HTML report: {e}")

# ==================== TEMPLATE (CSS/JS) ====================
TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <style>
        .bg-critical { background: linear-gradient(135deg, #7f1d1d, #b91c1c); color: white; }
        .bg-high     { background: linear-gradient(135deg, #9a3412, #ea580c); color: white; }
        .bg-medium   { background: linear-gradient(135deg, #854d0e, #ca8a04); color: white; }
        .bg-low      { background: linear-gradient(135deg, #164e63, #0891b2); color: white; }
        .bg-info     { background: linear-gradient(135deg, #1e293b, #475569); color: white; }

        .border-critical { border-left: 6px solid #f87171 !important; }
        .border-high     { border-left: 6px solid #fb923c !important; }
        .border-medium   { border-left: 6px solid #facc15 !important; }
        .border-low      { border-left: 6px solid #22d3ee !important; }
        .border-info     { border-left: 6px solid #94a3b8 !important; }
    </style> </head>
<body class="bg-[#0f1117] text-gray-200 font-sans">
    <div class="max-w-6xl mx-auto px-4 py-10">
        <header class="flex justify-between items-center mb-12 border-b border-gray-800 pb-6">
            <div class="flex items-center gap-3">
                <div class="p-3 bg-blue-600 rounded-lg"><i class="fa-solid fa-shield-halved text-white text-2xl"></i></div>
                <h1 class="text-3xl font-extrabold tracking-tight text-white">Security Report</h1>
            </div>
            <div class="text-right">
                <p class="text-sm text-gray-400 uppercase tracking-widest font-semibold">Total Findings</p>
                <p class="text-3xl font-mono text-blue-400">{{ total }}</p>
            </div>
        </header>

        <div class="flex space-x-1 border-b border-gray-800 mb-8 overflow-x-auto">
            {% for scanner in scanners %}
            <button onclick="switchTab('{{ scanner.id }}')" 
                    id="tab-{{ scanner.id }}"
                    class="tab px-6 py-3 text-sm font-medium transition-all hover:bg-[#1e1e2e] {% if loop.first %}tab-active{% endif %}">
                {{ scanner.name }} ({{ scanner.findings|length }})
            </button>
            {% endfor %}
        </div>

        {% for scanner in scanners %}
        <div id="content-{{ scanner.id }}" class="tab-content {% if not loop.first %}hidden{% endif %}">
            {% if scanner.findings %}
            <div class="space-y-4">
                {% for finding in scanner.findings %}
                    <div class="bg-zinc-900 rounded-xl p-5 border-l-4 border-zinc-800 hover:border-zinc-700 transition-all border-{{ finding.severity }}">                    <div class="flex items-start justify-between">
                        <span class="px-3 py-1 text-[10px] font-black uppercase tracking-wider rounded-md bg-{{ finding.severity }}">
                            {{ finding.severity }}
                        </span>
                        <span class="text-[11px] text-zinc-500 font-mono bg-black/30 px-2 py-1 rounded">
                            {{ finding.file }}{% if finding.line %}:{{ finding.line }}{% endif %}
                        </span>
                    </div>
                    <h3 class="mt-4 text-lg font-bold text-white leading-snug">
                        {{ finding.title }}
                    </h3>
                    <p class="text-zinc-400 mt-2 text-sm italic">
                        {{ finding.description }}
                    </p>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="py-20 text-center bg-zinc-900/50 rounded-xl border border-dashed border-zinc-800">
                <i class="fa-regular fa-circle-check text-5xl text-emerald-500 mb-4"></i>
                <p class="text-xl text-zinc-400">No vulnerabilities found.</p>
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    <script>
        function switchTab(id) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('tab-active'));
            document.getElementById('content-' + id).classList.remove('hidden');
            document.getElementById('tab-' + id).classList.add('tab-active');
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
