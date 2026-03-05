# 🛡️ DevSecOps Multi-Scanner Tool

A universal *__Docker-based__* security scanning tool for comprehensive source code analysis.

This container runs multiple security scanners, aggregates their findings, generates a *__single consolidated HTML report__*, and optionally uploads results to *__DefectDojo__*.

## 🚀 Features
__Flexible Scanner Selection__

Run only the tools you need. The container includes multiple security scanners such as:

- Semgrep
- Trivy
- Bandit
- Gitleaks
- Gosec
- njscan
- Hadolint

__Consolidated Security Report__

All findings are merged into a *__single consolidated HTML report__* for easier analysis and sharing.

__DefectDojo Integration (Optional)__

If configured, the tool automatically uploads results to *__DefectDojo__* and attaches the generated HTML report.

__Quality Gate__

The container can fail *__CI/CD pipelines__* if vulnerabilities exceed the configured threshold.

## 🛠️ How It Works (Docker)

No Docker Compose is required.

You only need to:

1. Build the container

2. Mount your source code

3. Run the scan

## 📦 Build the Image
```docker
docker build --no-cache -t {DOCKER_NAME} .
```
## ▶️ Run the Scanner

When running the container you should mount:

| Mount              | Purpose                                |
| ------------------ | -------------------------------------- |
| `/src`             | Source code to scan                    |
| `/scanner/reports` | Folder where reports will be generated |


Example:
```docker
docker run --rm \
  -v "$(pwd)/my-project:/src" \
  -v "$(pwd)/reports:/scanner/reports" \
  {DOCKER_NAME}
```
## 📁 Preparing the Reports Folder

Create a folder for reports and give permissions for the container user:
```bash
mkdir reports
sudo chown 10001:10001 reports
```
## 📤 DefectDojo Integration (Optional)

If you want to automatically upload results to *__DefectDojo__*, pass the required environment variables:
```docker
docker run --rm \
  -v "${PWD}/{TARGET_NAME}:/scan-target:ro" \
  -v "$(pwd)/reports:/scanner/reports" \
  -e DOJO_URL="{URL}" \
  -e DOJO_TOKEN="{YOUR_KEY}" \
  -e ENGAGEMENT_ID="{ID}" \
  {DOCKER_NAME}
```
*Important: Read-only Mount*
```docker
-v "${PWD}/{TARGET_NAME}:/scan-target:ro"
```
The `:ro` flag means __read-only__.

This ensures the container __cannot modify your source code__ and can only read it during the scan.

This is an additional __security safeguard__ when scanning production or sensitive repositories.

## 📂 Reports Handling
__Option 1 — Use DefectDojo__

If you upload results to *__DefectDojo__*, mounting the reports folder is __not required__.

The container will still generate reports internally and upload them automatically.

__Option 2 — Local Reports__

If you are not using DefectDojo, mount the reports folder:
```docker
-v "$(pwd)/reports:/scanner/reports"
```
All reports will be saved locally.

__Option 3 — Copy Reports from Container__

If you forgot to mount the reports directory, you can still extract the results using:
```
docker cp <container_id>:/scanner/reports .
```
## 🔍 Automatic Target Detection

The tool can __automatically detect project type and languages__ inside `/src`.

Based on detected files it automatically launches the appropriate scanners.

For example:

| File Detected      | Scanner  |
| ------------------ | -------- |
| `requirements.txt` | Bandit   |
| `go.mod`           | Gosec    |
| `Dockerfile`       | Hadolint |
| Any code           | Semgrep  |
| Git repository     | Gitleaks |

## ⚙️ Run Individual Scanners

You can also run scanners __individually__ using the `TOOL` environment variable.

Example:
```docker
-e TOOL=semgrep
```
## ⚙️ Running Multiple Scanners

You can run __multiple scanners at the same time__ using the `TOOL` environment variable.

List the tools __separated by commas without spaces__.

Example:
```docker
docker run --rm \
  -v "$(pwd)/my-project:/src" \
  -v "$(pwd)/reports:/scanner/reports" \
  -e TOOL=semgrep,trivy,gitleaks \
  {DOCKER_NAME}
```
⚠️ Important:

Tools must be written __without spaces__.

Correct:
```
semgrep,trivy,gitleaks
```
Incorrect:
```
semgrep, trivy, gitleaks
```
### Default Behavior (Automatic Scanner Execution)

If the `TOOL` variable __is not specified__, the container will attempt to __run all available scanners__.

Some scanners may __automatically skip execution__ if they cannot find a valid target inside the `/src` directory.

Examples:

| File Detected      | Scanner Triggered |
| ------------------ | ----------------- |
| `Dockerfile`       | Hadolint          |
| `requirements.txt` | Bandit            |
| `go.mod`           | Gosec             |
| `package.json`     | njscan            |
| Any source code    | Semgrep           |
| Git repository     | Gitleaks          |


If a scanner does not detect a valid target, it will simply __skip execution without failing the scan__.

## 🔎 Included Security Scanners

### Semgrep

__Purpose__

Static Application Security Testing (SAST)

__Targets__

- Python
- Go
- Java
- JavaScript
- TypeScript
- many others

Detects:

- insecure coding patterns
- injection vulnerabilities
- authentication issues
- logic flaws

### Trivy

__Purpose__

Vulnerability scanning.

__Targets__

- container images
- file systems
- dependencies

Detects:

- CVEs
- vulnerable packages
- OS vulnerabilities

### Bandit

__Purpose__

Python security scanner.

__Targets__

- Python code

Detects:

- unsafe functions
- insecure cryptography
- command injection risks

### Gitleaks

__Purpose__

Secret detection.

__Targets__

- Git repositories
- source code

Detects:

- hardcoded passwords
- API tokens
- private keys
- credentials

### Gosec

__Purpose__

Security scanner for Go.

__Targets__

- Go applications
  
Detects:

- insecure functions
- unsafe randomness
- hardcoded secrets
- SQL injection risks

### Njscan

__Purpose__

Security scanner for NodeJS applications.

__Targets__

- JavaScript / NodeJS

Detects:

- dependency vulnerabilities
- insecure coding patterns

### Hadolint

__Purpose__

Dockerfile linter.

__Targets__

- Dockerfiles

Detects:

- insecure Docker configurations
- best practice violations
- container hardening issues

## 🛡️ Quality Gate

The container returns:

| Exit Code | Meaning                                           |
| --------- | ------------------------------------------------- |
| `0`       | No vulnerabilities above the configured threshold |
| `1`       | Critical / High / Medium vulnerabilities detected |

This allows CI/CD pipelines to __automatically fail builds__.

## ⚙️ Changing Quality Gate Rules

Quality gate logic is located in:
```
generate_report.py
```
Line __205__.

Example logic:
```python
high_risk_count = summary.get("critical", 0) + summary.get("high", 0)
medium_count = summary.get("medium", 0)

if high_risk_count > 0 or medium_count > 5:
    print(f"QUALITY_GATE_STATUS=FAILED (High: {high_risk_count}, Medium: {medium_count})")
else:
    print("QUALITY_GATE_STATUS=PASSED")

with open(HTML_OUT, "w", encoding="utf-8") as f:
    f.write(Template(TEMPLATE).render(
        scanners=all_scanners, 
        total=len(all_findings_list),
        summary=summary
    ))
```
You can modify thresholds depending on your policy.

For example:

| Policy   | Example                   |
| -------- | ------------------------- |
| Strict   | Fail on any High          |
| Balanced | Fail on High or >5 Medium |
| Relaxed  | Fail only on Critical     |

## 📂 Project Structure
```
.
├── Dockerfile
├── entrypoint.sh
├── generate_report.py
└── reports/
```
| File               | Description                           |
| ------------------ | ------------------------------------- |
| entrypoint.sh      | Main scanning logic                   |
| generate_report.py | Aggregates results and generates HTML |
| Dockerfile         | Scanner environment                   |

## 📸 Screenshots
### Container Execution

(WIP)

Example:
```docker
docker run ...
```
### Generated HTML Report

(WIP)

### DefectDojo Report Upload

(WIP)
