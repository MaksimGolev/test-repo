#!/bin/bash
set -euo pipefail

# --- Configuration ---
SCAN_DIR="${SCAN_DIR:-.}"
REPORT_DIR="${REPORT_DIR:-/scanner/reports}"
SCAN_MODE="${SCAN_MODE:-full}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-HIGH}"

echo "Preparing reports directory..."
mkdir -p "$REPORT_DIR"
rm -rf "${REPORT_DIR:?}"/*

# --- Tool selection logic --- 
run_all=false
selected_tools=()

SELECTED="${TOOL:-${TOOLS:-all}}" 

if [ "$SELECTED" = "all" ]; then
    run_all=true
    echo "Running all scanners..."
else
    run_all=false
    IFS=',' read -r -a selected_tools <<< "$SELECTED"
    echo "Running selected scanners: ${selected_tools[*]}"
fi

# Helper function to check whether to run the tool
should_run() {
    local tool=$1
    [[ "$run_all" == "true" ]] && return 0
    if [ -n "${selected_tools[*]:-}" ]; then
        for t in "${selected_tools[@]}"; do
            [[ "$t" == "$tool" ]] && return 0
        done
    fi
    return 1
}

# --- Launching scanners ---
if should_run "semgrep"; then
    echo "→ Running Semgrep"
    semgrep scan --config="p/default" --no-git-ignore --sarif --output "$REPORT_DIR/semgrep.sarif" "$SCAN_DIR" || true
fi

if should_run "bandit"; then
    echo "→ Running Bandit"
    bandit -r "$SCAN_DIR" --format json -o "$REPORT_DIR/bandit.json" || true
fi

if should_run "nodejsscan"; then
    echo "→ Running njsscan (Modern SARIF mode)"
    njsscan "$SCAN_DIR" --sarif -o "$REPORT_DIR/nodejsscan.sarif" || true
fi

if should_run "gitleaks"; then
    echo "→ Running Gitleaks"
    gitleaks detect --source "$SCAN_DIR" --no-git --report-format json --report-path "$REPORT_DIR/gitleaks.json" || true
fi

if should_run "gosec"; then
    echo "→ Running Gosec (SARIF mode)"
    cd "$SCAN_DIR" && gosec -fmt sarif -out "$REPORT_DIR/gosec.sarif" ./... || true
    cd /scanner
fi

if should_run "hadolint"; then
    echo "→ Running Hadolint"
    DOCKERFILES=$(find "$SCAN_DIR" \( -name "Dockerfile*" -o -name "*.dockerfile" \))
    
    if [ -n "$DOCKERFILES" ]; then
        hadolint --format sarif $DOCKERFILES > "$REPORT_DIR/hadolint.sarif" || true
    else
        echo '{"version":"2.1.0","runs":[{"results":[]}]}' > "$REPORT_DIR/hadolint.sarif"
    fi
fi

if should_run "trivy"; then
    echo "→ Running Trivy"
    trivy fs --format sarif --output "$REPORT_DIR/trivy.sarif" --scanners vuln,secret,misconfig "$SCAN_DIR" || true
    trivy fs --format json --output "$REPORT_DIR/trivy.json" --scanners vuln,secret,misconfig "$SCAN_DIR" || true
    trivy fs --format template --template "@/scanner/templates/trivy-html.tpl" --output "$REPORT_DIR/trivy.html" --scanners vuln,secret,misconfig "$SCAN_DIR" || true
fi

# Integration with DefectDojo
if [ -n "${DOJO_URL:-}" ] && [ -n "${DOJO_TOKEN:-}" ]; then
    echo "→ DefectDojo integration enabled."
else
    echo "⚠️ DefectDojo variables not set, skipping upload."
fi

echo "→ Generating consolidated report..."
GEN_REPORT_LOG=$(python3 /scanner/generate_report.py)
echo "$GEN_REPORT_LOG"

# --- Upload Function ---
if [ -n "${DOJO_URL:-}" ] && [ -n "${DOJO_TOKEN:-}" ]; then
    echo "→ Uploading results to DefectDojo..."
    
    HTML_ALREADY_UPLOADED=0

    upload_to_dojo() {
        local file=$1
        local scan_type=$2
        [ ! -f "$file" ] && return

        local resp_file; resp_file=$(mktemp)
        local http_code; http_code=$(curl -s -o "$resp_file" -w "%{http_code}" -X POST \
            "$DOJO_URL/api/v2/import-scan/" \
            -H "Authorization: Token $DOJO_TOKEN" \
            -F "active=true" \
            -F "verified=true" \
            -F "scan_type=$scan_type" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "file=@$file")

        if [ "$http_code" -eq 201 ]; then
            local tid; tid=$(jq -r '.test' "$resp_file")
            echo " ✅ $scan_type uploaded (Test ID: $tid)"

            if [ "$HTML_ALREADY_UPLOADED" -eq 0 ]; then
                if [[ "$scan_type" == "SARIF" || "$scan_type" == "Semgrep OSS Scan" ]]; then
                    if [ -f "/scanner/reports/full_report.html" ]; then
                        echo " 📎 Attaching HTML report to Test ID: $tid..."

                        local unique_title="Consolidated_Report_$(date +%s)"

                        local attach_code; attach_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                            "$DOJO_URL/api/v2/tests/$tid/files/" \
                            -H "Authorization: Token $DOJO_TOKEN" \
                            -F "file=@/scanner/reports/full_report.html" \
                            -F "title=$unique_title")
                        
                        if [ "$attach_code" -eq 201 ]; then
                            echo " ✅ HTML report successfully attached."
                            HTML_ALREADY_UPLOADED=1
                        else
                            echo " ⚠️  Failed to attach HTML (HTTP $attach_code)"
                        fi
                    fi
                fi
            fi
        else
            echo " ❌ $scan_type upload failed (HTTP $http_code)"
            cat "$resp_file"
        fi
        rm -f "$resp_file"
    }

    upload_to_dojo "/scanner/reports/semgrep.sarif" "SARIF"
    upload_to_dojo "/scanner/reports/trivy.json" "Trivy Scan"
    upload_to_dojo "/scanner/reports/bandit.json" "Bandit Scan"
    upload_to_dojo "/scanner/reports/gitleaks.sarif" "SARIF"
    upload_to_dojo "/scanner/reports/nodejsscan.sarif" "SARIF"
    upload_to_dojo "/scanner/reports/gosec.sarif" "SARIF"
    upload_to_dojo "/scanner/reports/hadolint.sarif" "SARIF"

    echo "⌛ Waiting for Dojo to finalize (3s)..."
    sleep 3
fi

# --- Final analize Quality Gate ---
echo ""
echo "🔍 Quality Gate Analysis..."
echo "-------------------------------------------------------"

if echo "$GEN_REPORT_LOG" | grep -q "QUALITY_GATE_STATUS=FAILED"; then
    echo "❌ QUALITY GATE FAILED: Security risks detected!"
    echo "$GEN_REPORT_LOG" | grep -E "High risk:|Too many" || echo "Critical or High risk issues found."
    echo "-------------------------------------------------------"
    exit 1
else
    echo "✅ QUALITY GATE PASSED: All checks successful."
    echo "-------------------------------------------------------"
    exit 0
fi
