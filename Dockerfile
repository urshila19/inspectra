# Docker file for inspectra project
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    CHEF_LICENSE=accept \
    INSPEC_LICENSE=accept \
    INSPECTRA_VERSION=3.0.2 \
    PATH=/opt/inspec/bin:/opt/inspec/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up working directory
WORKDIR /inspectra

# Create app directory structure first
RUN mkdir -p /app/os_controls /app/webserver_controls /app/reports /app/test

# Install dependencies and InSpec using Chef's official RPM method
RUN apt-get update && \
    apt-get install -y sudo bash git locales wget rpm2cpio cpio curl ruby && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    wget "https://packages.chef.io/files/stable/inspec/5.22.3/el/7/inspec-5.22.3-1.el7.x86_64.rpm" -O /tmp/inspec.rpm && \
    cd / && rpm2cpio /tmp/inspec.rpm | cpio -idmv && \
    rm -rf /tmp/inspec.rpm

# Remove private keys from base image for compliance
RUN rm -f \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/httpclient-2.8.3/sample/ssl/0key.pem \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/httpclient-2.8.3/sample/ssl/1000key.pem \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/mongo-2.13.2/spec/support/certificates/client-encrypted.key \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/mongo-2.13.2/spec/support/certificates/client-second-level.key \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/mongo-2.13.2/spec/support/certificates/client-x509.key \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/mongo-2.13.2/spec/support/certificates/client.key \
  /opt/inspec/embedded/lib/ruby/gems/3.1.0/gems/mongo-2.13.2/spec/support/certificates/server-second-level.key

# Create inspectra user with same UID as typical host user (but don't switch to it for CI/CD)
RUN groupadd -g 1000 inspectra && \
    useradd -u 1000 -g inspectra -m -s /bin/bash inspectra && \
    echo "inspectra ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Copy InSpec profiles to the correct locations
COPY inspectra-webserver/src/ /app/webserver_controls/
COPY inspectra-os/src/ /app/os_controls/

# Copy webserver content detector
COPY inspectra-webserver/webserver_content_detector.rb /usr/local/bin/webserver_content_detector.rb
RUN chmod +x /usr/local/bin/webserver_content_detector.rb

# ===== NEW: Copy custom report generator =====
COPY inspectra-webserver/report_generator.rb /usr/local/bin/report_generator.rb
RUN chmod +x /usr/local/bin/report_generator.rb
# ===== END NEW SECTION =====

# Create entrypoint script with webserver detection
RUN cat <<'EOF' > /usr/local/bin/docker-entrypoint.sh
#!/bin/bash
set -e

# Ensure reports directory exists and is writable
ensure_reports_writable() {
  mkdir -p /app/reports
  chmod 777 /app/reports 2>/dev/null || true
  
  # Debug information
  echo "DEBUG: Current user: $(whoami) (UID: $(id -u), GID: $(id -g))"
  echo "DEBUG: Reports directory permissions:"
  ls -la /app/ | grep reports || echo "Reports directory not found"
}

show_help() {
  echo "InSpectra - Security Compliance Scanner v3.0"
  echo "Intelligent webserver detection and compliance scanning"
  echo ""
  echo "Usage:"
  echo "  docker run [OPTIONS] inspectra [webserver|os|help]"
  echo ""
  echo "Simplified Usage (Auto-detection):"
  echo "  docker run -v /reports:/app/reports -v /path/to/configs:/app/scan inspectra webserver"
  echo ""
  echo "Examples:"
  echo "  docker run -v /tmp/reports:/app/reports -v /etc/apache2:/app/scan inspectra webserver"
  echo "  docker run -v /tmp/reports:/app/reports -v /etc/nginx:/app/scan inspectra webserver"
  echo "  docker run -v /tmp/reports:/app/reports -v /opt/tomcat/conf:/app/scan inspectra webserver"
  echo ""
  echo "Note: The webserver type is automatically detected from configuration files."
}

detect_webserver_type() {
  local scan_dir="$1"
  
  echo "=== Intelligent Webserver Detection ==="
  echo "Scanning directory: $scan_dir"
  
  # Run the webserver content detector
  export SCAN_DIR="$scan_dir"
  export REPORT_FILE="/tmp/detection_report.txt"
  
  if ! ruby /usr/local/bin/webserver_content_detector.rb > /tmp/detector_output.log 2>&1; then
    echo "ERROR: Webserver detection failed"
    cat /tmp/detector_output.log
    return 1
  fi
  
  # Parse the detection output for the highest confidence detection
  if [ -f "/tmp/detection_report.txt" ]; then
    # Look for the PRIMARY_DETECTION section for machine-readable output
    DETECTED_TYPE=$(grep "PRIMARY_WEBSERVER_TYPE=" /tmp/detection_report.txt 2>/dev/null | cut -d'=' -f2)
    
    if [ -n "$DETECTED_TYPE" ]; then
      CONFIDENCE=$(grep "PRIMARY_CONFIDENCE=" /tmp/detection_report.txt 2>/dev/null | cut -d'=' -f2)
      PRIORITY=$(grep "PRIMARY_PRIORITY=" /tmp/detection_report.txt 2>/dev/null | cut -d'=' -f2)
      DETECTED_FILE=$(grep "PRIMARY_FILE=" /tmp/detection_report.txt 2>/dev/null | cut -d'=' -f2)
      
      echo "Detected webserver type: $DETECTED_TYPE (confidence: $CONFIDENCE, priority: $PRIORITY)"
      echo "Primary detection file: $DETECTED_FILE"
      echo ""
      echo "Full detection report:"
      cat /tmp/detection_report.txt
      echo ""
      echo "$DETECTED_TYPE"
      return 0
    fi
  fi
  
  echo "No webserver configuration detected"
  echo "Detection log:"
  cat /tmp/detector_output.log
  echo ""
  echo "Available profiles:"
  ls -la /app/webserver_controls/ 2>/dev/null || echo "  (none found)"
  return 1
}

run_webserver_scan() {
  echo "=== InSpectra Webserver Compliance Scan ==="
  echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  
  # Ensure reports directory is writable
  ensure_reports_writable
  
  # Check for mounted configuration directory
  SCAN_DIRECTORY="/app/scan"
  
  if [ ! -d "$SCAN_DIRECTORY" ]; then
    echo "ERROR: Scan directory not found: $SCAN_DIRECTORY"
    echo "Please mount your webserver configuration directory to: $SCAN_DIRECTORY"
    echo ""
    echo "Example:"
    echo "  docker run -v /etc/apache2:/app/scan -v /tmp/reports:/app/reports inspectra webserver"
    exit 1
  fi
  
  # Detect webserver type automatically
  echo ""
  echo "=== Starting Webserver Detection ==="
  
  # Run detection and capture both output and return value
  DETECTION_OUTPUT=$(detect_webserver_type "$SCAN_DIRECTORY" 2>&1)
  DETECTION_EXIT_CODE=$?
  
  # Extract just the webserver type from the last line
  WEBSERVER_TYPE=$(echo "$DETECTION_OUTPUT" | tail -1)
  
  # Show the detection output 
  echo "$DETECTION_OUTPUT" | head -n -1
  
  echo ""
  echo "DEBUG: Extracted webserver type: '$WEBSERVER_TYPE'"
  
  if [ $DETECTION_EXIT_CODE -ne 0 ] || [ -z "$WEBSERVER_TYPE" ] || [ "$WEBSERVER_TYPE" = "No webserver configuration detected" ]; then
    echo "ERROR: Could not detect webserver type from configuration files"
    echo "Please ensure the directory contains valid webserver configuration files"
    exit 1
  fi
  
  echo ""
  echo "=== Webserver Profile Validation ==="
  
  # Check if we have InSpec profile for this webserver type
  PROFILE_PATH="/app/webserver_controls/$WEBSERVER_TYPE"
  if [ ! -d "$PROFILE_PATH" ]; then
    echo "ERROR: No InSpec profile found for webserver type: $WEBSERVER_TYPE"
    echo "Available profiles:"
    ls -la /app/webserver_controls/ 2>/dev/null || echo "  (none found)"
    exit 1
  fi
  
  echo "Using InSpec profile: $PROFILE_PATH"
  
  # Ensure reports directory exists
  mkdir -p /app/reports

  DETECTION_REPORT="/tmp/detection_report.txt"

  # --- TOMCAT SCAN LOGIC ---
  if [[ "$WEBSERVER_TYPE" =~ ^tomcat ]]; then
    # Collect all detected Tomcat config files
    mapfile -t DETECTED_CONFIGS < <(awk "/^${WEBSERVER_TYPE^^} DETECTED:/,/^$/" "$DETECTION_REPORT" | awk '/Full Path: /{print $3}')
    if [ ${#DETECTED_CONFIGS[@]} -eq 0 ]; then
      echo "ERROR: No configuration files detected for $WEBSERVER_TYPE"
      exit 1
    fi
    # Create single input file listing all configs
    INPUT_FILE="/tmp/${WEBSERVER_TYPE}_compiled_inputs.yml"
    echo "# Compiled input file for $WEBSERVER_TYPE" > "$INPUT_FILE"
    echo "# Contains all detected config files" >> "$INPUT_FILE"
    echo "all_config_files:" >> "$INPUT_FILE"
    for CONF_FILE in "${DETECTED_CONFIGS[@]}"; do
      echo "  - \"$CONF_FILE\"" >> "$INPUT_FILE"
    done
    echo "test_dir: \"$SCAN_DIRECTORY\"" >> "$INPUT_FILE"
    cat "$INPUT_FILE"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    REPORT_BASE="${WEBSERVER_TYPE}_compiled_scan_report_${TIMESTAMP}"
    echo ""
    echo "=== Running compiled Tomcat scan for configs: ==="
    printf '%s\n' "${DETECTED_CONFIGS[@]}"
    
    # ===== MODIFIED: Generate both JSON and custom HTML =====
    inspec exec "$PROFILE_PATH" --input-file "$INPUT_FILE" \
      --reporter "json:/app/reports/${REPORT_BASE}.json" \
      --chef-license accept --log-level warn || true
    
    # Generate custom HTML report
    export CONFIG_FILE="${DETECTED_CONFIGS[0]}"  # Use first config as reference
    export SERVER_TYPE="$WEBSERVER_TYPE"
    export INSPECTRA_VERSION="3.0.2"
    export SCAN_TIME="$(date -u +%Y-%m-%d\ %H:%M:%S)"
    
    echo "Generating custom HTML report..."
    ruby /usr/local/bin/report_generator.rb \
      "/app/reports/${REPORT_BASE}.json" \
      "/app/reports/${REPORT_BASE}.html"
    # ===== END MODIFIED SECTION =====
    
    echo "Reports generated:"
    ls -la /app/reports/${REPORT_BASE}* 2>/dev/null || echo "No reports generated"
    echo "=== Tomcat compiled scan completed ==="
    return
  fi
  # --- END TOMCAT SCAN LOGIC ---

  # --- IBM HTTPD, IIS, JBoss, Nginx, IBM WebSphere: always run a separate scan per config file ---
  if [[ "$WEBSERVER_TYPE" =~ ^(ibm-httpd|iis|jboss|nginx|ibm-websphere)$ ]]; then
    mapfile -t DETECTED_CONFIGS < <(awk "/^${WEBSERVER_TYPE^^} DETECTED:/,/^$/" "$DETECTION_REPORT" | awk '/Full Path: /{print $3}')
    if [ ${#DETECTED_CONFIGS[@]} -eq 0 ]; then
      echo "ERROR: No configuration files detected for $WEBSERVER_TYPE"
      exit 1
    fi
    for CONF_FILE in "${DETECTED_CONFIGS[@]}"; do
      if [ ! -f "$CONF_FILE" ]; then
        echo "WARNING: Config file not found: $CONF_FILE"
        continue
      fi
      CONF_BASENAME=$(basename "$CONF_FILE")
      CONF_SAFE_NAME=$(echo "$CONF_BASENAME" | tr '.' '_' | tr -cd '[:alnum:]_')
      INSTANCE_INPUT="/tmp/${WEBSERVER_TYPE}_${CONF_SAFE_NAME}_inputs.yml"
      echo "test_dir: \"$(dirname "$CONF_FILE")\"" > "$INSTANCE_INPUT"
      echo "config_file: \"$CONF_FILE\"" >> "$INSTANCE_INPUT"
      TIMESTAMP=$(date +%Y%m%d_%H%M%S)
      REPORT_BASE="${WEBSERVER_TYPE}_${CONF_SAFE_NAME}_scan_report_${TIMESTAMP}"
      echo ""
      echo "=== Scanning config: $CONF_FILE ==="
      echo "Input file: $INSTANCE_INPUT"
      echo "Report base: $REPORT_BASE"
      
      # ===== MODIFIED: Generate both JSON and custom HTML =====
      # Run InSpec for this config file with JSON output
      inspec exec "$PROFILE_PATH" --input-file "$INSTANCE_INPUT" \
        --reporter "json:/app/reports/${REPORT_BASE}.json" \
        --chef-license accept --log-level warn || true
      
      # Generate custom HTML report using our report generator
      export CONFIG_FILE="$CONF_FILE"
      export SERVER_TYPE="$WEBSERVER_TYPE"
      export INSPECTRA_VERSION="3.0.2"
      export SCAN_TIME="$(date -u +%Y-%m-%d\ %H:%M:%S)"
      
      echo "Generating custom HTML report..."
      ruby /usr/local/bin/report_generator.rb \
        "/app/reports/${REPORT_BASE}.json" \
        "/app/reports/${REPORT_BASE}.html"
      # ===== END MODIFIED SECTION =====
      
      echo "Reports generated for $CONF_BASENAME:"
      ls -la /app/reports/${REPORT_BASE}* 2>/dev/null || echo "No reports generated"
    done
    echo ""
    echo "=== All scans completed for detected configs ==="
    ls -la /app/reports/
    echo ""
    echo "InSpectra webserver scan completed!"
    return
  fi
  # --- END IBM HTTPD, IIS, JBoss, Nginx, IBM WebSphere logic ---

  # --- default per-config logic for other webservers ---
  mapfile -t DETECTED_CONFIGS < <(awk "/^${WEBSERVER_TYPE^^} DETECTED:/,/^$/" "$DETECTION_REPORT" | awk '/Full Path: /{print $3}')
  if [ ${#DETECTED_CONFIGS[@]} -eq 0 ]; then
    echo "ERROR: No configuration files detected for $WEBSERVER_TYPE"
    exit 1
  fi
  for CONF_FILE in "${DETECTED_CONFIGS[@]}"; do
    if [ ! -f "$CONF_FILE" ]; then
      echo "WARNING: Config file not found: $CONF_FILE"
      continue
    fi
    CONF_BASENAME=$(basename "$CONF_FILE")
    CONF_SAFE_NAME=$(echo "$CONF_BASENAME" | tr '.' '_' | tr -cd '[:alnum:]_')
    INSTANCE_INPUT="/tmp/${WEBSERVER_TYPE}_${CONF_SAFE_NAME}_inputs.yml"
    echo "test_dir: \"$(dirname "$CONF_FILE")\"" > "$INSTANCE_INPUT"
    echo "config_file: \"$CONF_FILE\"" >> "$INSTANCE_INPUT"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    REPORT_BASE="${WEBSERVER_TYPE}_${CONF_SAFE_NAME}_scan_report_${TIMESTAMP}"
    echo ""
    echo "=== Scanning config: $CONF_FILE ==="
    echo "Input file: $INSTANCE_INPUT"
    echo "Report base: $REPORT_BASE"
    
    # ===== MODIFIED: Generate both JSON and custom HTML =====
    # Run InSpec for this config file with JSON output
    inspec exec "$PROFILE_PATH" --input-file "$INSTANCE_INPUT" \
      --reporter "json:/app/reports/${REPORT_BASE}.json" \
      --chef-license accept --log-level warn || true
    
    # Generate custom HTML report using our report generator
    export CONFIG_FILE="$CONF_FILE"
    export SERVER_TYPE="$WEBSERVER_TYPE"
    export INSPECTRA_VERSION="3.0.2"
    export SCAN_TIME="$(date -u +%Y-%m-%d\ %H:%M:%S)"
    
    echo "Generating custom HTML report..."
    ruby /usr/local/bin/report_generator.rb \
      "/app/reports/${REPORT_BASE}.json" \
      "/app/reports/${REPORT_BASE}.html"
    # ===== END MODIFIED SECTION =====
    
    echo "Reports generated for $CONF_BASENAME:"
    ls -la /app/reports/${REPORT_BASE}* 2>/dev/null || echo "No reports generated"
  done
  echo ""
  echo "=== All scans completed for detected configs ==="
  ls -la /app/reports/
  echo ""
  echo "InSpectra webserver scan completed!"
}

run_os_scan() {
  echo "=== InSpectra OS Compliance Scan ==="
  echo "OS scanning not yet implemented in this version"
  exit 1
}

case "${1:-help}" in
  webserver)
    run_webserver_scan
    ;;
  os)
    run_os_scan
    ;;
  help|--help|-h|"")
    show_help
    ;;
  *)
    echo "Unknown command: $1"
    show_help
    exit 1
    ;;
esac
EOF

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set ownership and permissions for inspectra user
RUN chown -R inspectra:inspectra /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/reports

# Create volume mount points
VOLUME ["/app/reports", "/app/scan"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD inspec version || exit 1

# Set user to inspectra for compliance
USER inspectra

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["help"]