# Inspectra

Inspectra integrates automated compliance scanning into CI/CD pipelines for Web and Application servers using InSpec profiles. It automatically detects webserver type from configuration files, applies relevant InSpec controls based on industry benchmarks and the IRM team's SCDs at KMBL, and generates comprehensive compliance reports in multiple formats for artifact publishing.

## Features
- Automatic Webserver Detection — Identifies webserver type from configuration files
- Pattern-Based Recognition — Uses regex patterns and scoring algorithms
- Multi-Format Support — Scans XML, properties, and other configuration files recursively
- InSpec-based Controls — Uses community/organization InSpec profiles for checks and reporting
- CI/CD Friendly — Designed to run in pipeline agents and publish HTML/JSON reports

## Supported Web / App Server Types
- `apache` — Apache HTTP Server
- `nginx` — Nginx Web Server
- `iis` — Microsoft IIS
- `jboss` — JBoss EAP
- `tomcat7` — Apache Tomcat 7
- `tomcat8` — Apache Tomcat 8
- `tomcat9` — Apache Tomcat 9
- `tomcat-windows` — Apache Tomcat (Windows)
- `ibm-httpd` — IBM HTTP Server
- `ibm-websphere` — IBM WebSphere

## How to Integrate Inspectra in Your Pipeline

### 1) Include Inspectra Template in Your Pipeline
Add the Inspectra template repository as a resource in your pipeline YAML:

```yaml
resources:
  repositories:
    - repository: riskIntelTemplate
      type: git
      name: "Builder Tools/risk-intel-template"
      ref: refs/heads/inspectra-templates
```

### 2) Add Inspectra Compliance Step to Your Pipeline
Add the Inspectra compliance step to your pipeline definition. Example Azure DevOps stage/job:

```yaml
stages:
  - stage: InspectraScan
    displayName: "Webserver Compliance Scan"
    jobs:
      - job: InspectraWebserverCompliance
        displayName: "Run Inspectra Webserver Compliance Scan"
        steps:
          - template: templates/inspectra_webserver_template.yml@riskIntelTemplate
            parameters:
              webserverConfigPath: '<path to config files, e.g., /app/config/apache>'
```

Replace parameter values to match your repository or artifact layout.

### 3) Review Scan Reports
After pipeline execution, published artifacts will contain the generated compliance reports. Example artifact layout:

```
inspectra-reports/
├── apache.html      # Compliance report (HTML)
├── apache.json      # Machine-readable results (JSON)
└── ...
```

You can open the HTML reports in a browser or ingest the JSON for dashboards/automation.


