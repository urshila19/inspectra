# =============================================================================
# Apache Web Server Security Controls
# =============================================================================
# This InSpec profile validates security configurations for Apache web server
# by checking configuration files for proper security settings.
# =============================================================================

title 'Apache Server Config'

# Allow users to override the test directory path at runtime:
test_dir = attribute('test_dir', description: 'The base path for test config files', value: '/app/test/apache')

# Validate test directory exists and is readable
unless Dir.exist?(test_dir)
  raise "Test directory does not exist: #{test_dir}"
end

# Define config file patterns for Apache (recursive search)
CONFIG_PATTERNS = [
  "#{test_dir}/**/*.conf",
  "#{test_dir}/**/httpd.conf",
  "#{test_dir}/**/apache2.conf",
  "#{test_dir}/**/ssl.conf",
  "#{test_dir}/**/security.conf",
  "#{test_dir}/**/hardening.conf"
]

CONFIG_FILES = []
CONFIG_PATTERNS.each do |pattern|
  Dir.glob(pattern).each do |f|
    CONFIG_FILES << f if File.exist?(f) && File.readable?(f)
  end
end

# Remove duplicates that might be found by multiple patterns
CONFIG_FILES.uniq!

# Check if any config files exist
any_config_exists = !CONFIG_FILES.empty?

# Only execute security controls if at least one Apache configuration file exists
if any_config_exists

  # 1. Enable Only Necessary Authentication and Authorization Module
  control 'apache-auth-modules' do
    impact 1.0
    title 'Enable Only Necessary Authentication and Authorization Module'
    desc 'The Apache 2.4 modules for authentication and authorization are grouped and named to provide both granularity, and a consistent naming convention to simplify configuration. The authn_*modules provide authentication, while the authz_* modules provide authorization. Apache provides two types of authentication - basic and digest. Review the Apache Authentication and Authorization how-to documentation http://httpd.apache.org/docs/2.4/howto/auth.html and enable only the modules that are required.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Authentication and authorization are the front doors to the protected information in your website. Most installations only need a small subset of the modules available. By minimizing the enabled modules to those that are actually used, we reduce the number of "doors" and therefore reduce the attack surface of the website. Likewise, having fewer modules means less software that could have vulnerabilities.'
    tag remediation: 'Consult Apache module documentation for descriptions of each module in order to determine the necessary modules for the specific installation.
    http://httpd.apache.org/docs/2.4/mod/
    The unnecessary static compiled modules are disabled through compile time configuration options asdocumented in http://httpd.apache.org/docs/2.4/programs/configure.html. 
    The dynamically loaded modules are disabled by commenting out or removing the LoadModule directive from the Apache configuration files (typically httpd.conf). Some modules may be separate packages,and may be removed.
    Default Value:
    The following modules are loaded by a default source build:
    authn_file_module (shared)
    authn_core_module (shared)
    authz_host_module (shared)
    authz_groupfile_module(shared)
    authz_user_module (shared)
    authz_core_module (shared)
    References: 1. https://httpd.apache.org/docs/2.4/howto/auth.html2. https://httpd.apache.org/docs/2.4/mod/3. https://httpd.apache.org/docs/2.4/programs/configure.html'
    tag vulnerability_id: 'Apache-001'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Enable Only Necessary Authentication and Authorization Module'
    
    # List the ONLY modules that should be enabled for your deployment
    REQUIRED_AUTH_MODULES = [
      'authn_file_module',
      'authn_core_module',
      'authz_host_module',
      'authz_groupfile_module',
      'authz_user_module',
      'authz_core_module'
      # Add or remove as per your policy
    ]

    loaded_auth_modules = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines
          .map(&:strip)
          .reject { |line| line.empty? || line.start_with?('#') }
          .each do |line|
            if line =~ /^LoadModule\s+(auth[nz]_[a-z_]+_module)/
              loaded_auth_modules << $1
            end
          end
      end
    end

    loaded_auth_modules.uniq!

    # Find modules loaded but not required
    extra_modules = loaded_auth_modules - REQUIRED_AUTH_MODULES
    # Find required modules missing
    missing_modules = REQUIRED_AUTH_MODULES - loaded_auth_modules

    describe 'Apache: Enable only necessary authentication and authorization modules' do
      it 'should not have extra auth modules loaded' do
        expect(extra_modules).to be_empty
      end
      it 'should have all required auth modules loaded' do
        expect(missing_modules).to be_empty
      end
    end
  end

  # 2. Enable the Log Config Module
  control 'apache-log-config-module' do
    impact 1.0
    title 'Enable the Log Config Module'
    desc 'The log_config module provides for flexible logging of client requests, and provides for theconfiguration of the information in each log.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Logging is critical for monitoring usage and potential abuse of your web server. This module is required to configure web server logging using the log_format directive.'
    tag remediation: 'Perform either one of the following:
    • For source builds with static modules, run the Apache ./configure script withoutincluding the --disable-log-config script options.
    $ cd $DOWNLOAD_HTTPD$ ./configure
    • For dynamically loaded modules, add or modify the Load Module directive so that it ispresent in the apache configuration as below and not commented out:
    LoadModule log_config_module modules/mod_log_config.so
    Default Value:
    The log_config module is loaded by default.
    References: 1. https://httpd.apache.org/docs/2.4/mod/mod_log_config.html'
    tag vulnerability_id: 'Apache-002'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Enable the Log Config Module'
    
    found_log_config = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule log_config_module/) }
          found_log_config = true
          break
        end
      end
    end
    
    describe 'Apache: Enable the Log Config Module' do
      it 'should include log_config_module in at least one config file' do
        expect(found_log_config).to be true
      end
    end
  end

  # 3. Disable WebDAV Modules
  control 'apache-disable-webdav' do
    impact 1.0
    title 'Disable WebDAV Modules'
    desc 'The Apache mod_dav and mod_dav_fs modules support WebDAV (Web-based Distributed Authoring and Versioning) functionality for Apache. WebDAV is an extension to the HTTP protocol which allows clients to create, move, and delete files and resources on the web server.'

    # Custom tags for report generation
    tag risk_rating: 'High'
    tag severity: 'High'
    tag impact_description: 'Disabling WebDAV modules will improve the security posture of the web server by reducing the amount of potentially vulnerable code paths exposed to the network and reducing potential for unauthorized access to files via misconfigured WebDAV access controls.'
    tag remediation: 'Perform either one of the following to disable WebDAV module:
    1. For source builds with static modules run the Apache ./configure script without including the mod_dav, and mod_dav_fs in the --enable-modules= configure script options.
    $ cd
    $DOWNLOAD_HTTPD
    $ ./configure
    2. For dynamically loaded modules comment out or remove the LoadModule directive for mod_dav, and mod_dav_fs modules from the httpd.conf file.
    #
    #LoadModule dav_module modules/mod_dav.so
    #
    #LoadModule dav_fs_module modules/mod_dav_fs.so
    Default Value:
    The WebDav modules are not enabled with a default source build.
    References: 1. https://httpd.apache.org/docs/2.4/mod/mod_dav.html'
    tag vulnerability_id: 'Apache-003'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable WebDAV Modules'
    
    found_dav_modules = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule (dav_module|dav_fs_module|dav_lock_module)/) }
          found_dav_modules = true
          break
        end
      end
    end
    
    describe 'Apache: Disable WebDAV Modules' do
      it 'should not include dav modules in any config file' do
        expect(found_dav_modules).to be false
      end
    end
  end

  # 4. Disable Status Module
  control 'apache-disable-status' do
    impact 1.0
    title 'Disable Status Module'
    desc 'The Apache mod_status module provides current server performance statistics.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'When mod_status is loaded into the server, its handler capability is available in all configuration files, including per-directory files (e.g., .htaccess). The mod_status module may provide an adversary with information that can be used to refine exploits that depend on measuring server load.'
    tag remediation: 'Perform either one of the following to disable the mod_status module:
    1. For source builds with static modules, run the Apache ./configure script with the --disable-status configure script options.
    $ cd 
    $DOWNLOAD_HTTPD
    $ ./configure --disable-status
    2. For dynamically loaded modules, comment out or remove the LoadModule directive for the mod_status module from the httpd.conf file.
    #
    #LoadModule status_module modules/mod_status.so
    Default Value:
    The mod_status module IS enabled with a default source build.
    References: 1. https://httpd.apache.org/docs/2.4/mod/mod_status.html"'
    tag vulnerability_id: 'Apache-004'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable Status Module'
    
    found_status_module = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule status_module/) }
          found_status_module = true
          break
        end
      end
    end
    
    describe 'Apache: Disable Status Module' do
      it 'should not include status_module in any config file' do
        expect(found_status_module).to be false
      end
    end
  end

  # 5. Disable Autoindex Module
  control 'apache-disable-autoindex' do
    impact 1.0
    title 'Disable Autoindex Module'
    desc 'The Apache auto index module automatically generates web page listing the contents of directories on the server, typically used so that an index.html does not have to be generated.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Automated directory listings should not be enabled as it will also reveal information helpful to an attacker such as naming conventions and directory paths. Directory listings may also reveal files that were not intended to be revealed.'
    tag remediation: 'Perform either one of the following to disable the mod_autoindex module:
    1. For source builds with static modules, run the Apache ./configure script with the --disable-autoindex configure script options
    $ cd 
    $DOWNLOAD_HTTPD
    $ ./configure -disable-autoindex
    2. For dynamically loaded modules, comment out or remove the LoadModule directive for mod_autoindex from the httpd.conf file.
    #
    # LoadModule autoindex_module modules/mod_autoindex.so
    Default Value:
    The mod_autoindex module IS enabled with a default source build.
    References: 1. https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html'
    tag vulnerability_id: 'Apache-005'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable Autoindex Module'
    
    found_autoindex_module = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule autoindex_module/) }
          found_autoindex_module = true
          break
        end
      end
    end
    
    describe 'Apache: Disable Autoindex Module' do
      it 'should not include autoindex_module in any config file' do
        expect(found_autoindex_module).to be false
      end
    end
  end

  # 6. Disable Proxy Modules
  control 'apache-disable-proxy' do
    impact 1.0
    title 'Disable Proxy Modules'
    desc 'The Apache proxy modules allow the server to act as a proxy (either forward or reverse proxy)of HTTP and other protocols with additional proxy modules loaded. If the Apache installation is not intended to proxy requests tr from another network then the proxy module should not be loaded.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Proxy servers can act as an important security control when properly configured, however a secure proxy server is not within the scope of this benchmark. A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests is a very common attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying requests into an otherwise protected network.'
    tag remediation: 'Perform either one of the following to disable the proxy module:
    1. For source builds with static modules, run the Apache ./configure script withoutincluding the mod_proxy in the --enable-modules=configure script options.
    $ cd 
    $DOWNLOAD_HTTPD
    $ ./configure
    2. For dynamically loaded modules, comment out or remove the LoadModule directive for mod_proxy module and all other proxy modules from the httpd.conf file.
    #
    #LoadModule proxy_module modules/mod_proxy.so
    #
    #LoadModule proxy_connect_module modules/mod_proxy_connect.so
    #
    #LoadModule proxy_ftp_module modules/mod_proxy_ftp.so
    #
    #LoadModule proxy_http_module modules/mod_proxy_http.so
    #
    #LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so
    #
    #LoadModule proxy_scgi_module modules/mod_proxy_scgi.so
    #
    #LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
    #
    #LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
    #
    #LoadModule proxy_express_module modules/mod_proxy_express.so
    #
    #LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
    #
    #LoadModule proxy_fdpass_module modules/mod_proxy_fdpass.so
    Default Value:
    The mod_proxy module and other proxy modules are NOT enabled with a default source build.
    References: 1. https://httpd.apache.org/docs/2.4/mod/mod_proxy.html'
    tag vulnerability_id: 'Apache-006'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable Proxy Modules'
    
    found_proxy_modules = false

    proxy_modules = [
      'proxy_module',
      'proxy_http_module',
      'proxy_ftp_module',
      'proxy_connect_module',
      'proxy_fcgi_module',
      'proxy_scgi_module',
      'proxy_ajp_module',
      'proxy_balancer_module',
      'proxy_express_module',
      'proxy_wstunnel_module',
      'proxy_fdpass_module'
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                         .map(&:strip)
                                         .reject { |line| line.empty? || line.start_with?('#') }

        if content_lines.any? { |line| line.match?(/^LoadModule (#{proxy_modules.join('|')})/) }
          found_proxy_modules = true
          break
        end
      end
    end

    describe 'Apache: Disable Proxy Modules' do
      it 'should not include proxy modules in any config file' do
        expect(found_proxy_modules).to be false
      end
    end
  end

  # 7. Disable User Directories Modules
  control 'apache-disable-userdir' do
    impact 1.0
    title 'Disable User Directories Modules'
    desc 'The User Dir directive must be disabled so that user home directories are not accessed via theweb site with a tilde (~) preceding the username. The directive also sets the path name of the directory that will be accessed. For example:
    • http://example.com/~ralph/ might access a public_html sub-directory of ralph users home directory.
    • The directive UserDir ./ might map /~root to the root directory (/).'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The user directories should not be globally enabled since it allows anonymous access to anything users may want to share with other users on the network. Also consider that every time a new account is created on the system, there is potentially new content available via the web site.'
    tag remediation: 'Perform either one of the following to disable the user directories module:
    1. For source builds with static modules, run the Apache ./configure script with the --disable-userdir configure script options.
    $ cd 
    $DOWNLOAD_HTTPD
    $ ./configure --disable-userdir
    2. For dynamically loaded modules, comment out or remove the LoadModule directive for mod_userdir module from the httpd.conf file.
    #
    #LoadModule userdir_module modules/mod_userdir.so
    Default Value:
    The mod_userdir module is not enabled with a default source build.
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_userdir.html'
    tag vulnerability_id: 'Apache-007'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable User Directories Modules'
    
    found_userdir_module = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule userdir_module/) }
          found_userdir_module = true
          break
        end
      end
    end
    
    describe 'Apache: Disable User Directories Modules' do
      it 'should not include userdir_module in any config file' do
        expect(found_userdir_module).to be false
      end
    end
  end

  # 8. Disable Info Module
  control 'apache-disable-info' do
    impact 1.0
    title 'Disable Info Module'
    desc 'The Apache mod_info module provides information on the server configuration via access to a/server-info URL location.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'While having server configuration information available as a web page may be convenient it is recommended that this module NOT be enabled. Once mod_info is loaded into the server, its handler capability is available in per-directory .htaccess files and can leak sensitive information from the configuration directives of other Apache modules such as system paths, usernames/passwords, database names, etc.'
    tag remediation: 'Perform either one of the following to disable the mod_info module:
    1. For source builds with static modules, run the Apache ./configure script withoutincluding the mod_info in the --enable-modules= configure script options.
    $ cd 
    $DOWNLOAD_HTTPD
    $ ./configure
    2. For dynamically loaded modules, comment out or remove the LoadModule directive for the mod_info module from the httpd.conf file.
    #
    #LoadModule info_module modules/mod_info.so
    Default Value:
    The mod_info module is not enabled with a default source build.
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_info.html'
    tag vulnerability_id: 'Apache-008'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable Info Module'
    
    found_info_module = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule info_module/) }
          found_info_module = true
          break
        end
      end
    end
    
    describe 'Apache: Disable Info Module' do
      it 'should not include info_module in any config file' do
        expect(found_info_module).to be false
      end
    end
  end

  # 9. Allow Appropriate Access to Web Content
  control 'apache-allow-web-content-access' do
    impact 1.0
    title 'Allow Appropriate Access to Web Content'
    desc 'In order to serve Web content, either the Apache Allow directive or the Require directive will need to be used to allow for appropriate access to directories, locations and virtual hosts that contain web content.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Either the Allow or Require directives may be used within a directory, a location or other context to allow appropriate access. Access may be allowed to all, or to specific networks, or hosts, or users as appropriate. The Allow/Deny/Order directives are deprecated and should be replaced by the Require directive. It is also recommended that either the Allow directive or the Require directive be used, but not both in the same context.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find all <Directory> and <Location> elements. There should be one for thedocument root and any special purpose directories or locations. There are likely to beother access control directives in other contexts, such as virtual hosts or special elementslike <Proxy>.
    2. Include the appropriate Require directives, with values that are appropriate for thepurposes of the directory.
    The configurations below are just a few possible examples.
    <Directory ""/var/www/html/"">Require ip 192.169.</Directory>
    <Directory ""/var/www/html/"">Require all granted</Directory>
    <Location /usage>Require local</Location>
    <Location /portal>Requirevalid-user</Location>
    Default Value:
    The following is the default Web root directory configuration:<Directory ""/usr/local/apache2/htdocs"">. . .Require all granted. . .</Directory>
    References:
    1. https://httpd.apache.org/docs/2.4/mod/core.html
    #directory
    2. https://httpd.apache.org/docs/2.4/mod/mod_authz_host.html
    3. https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html
    4. https://httpd.apache.org/docs/2.4/mod/mod_access_compat.html'
    tag vulnerability_id: 'Apache-009'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Allow Appropriate Access to Web Content'
    
    require_blocks_without_require = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find all <Directory ...>...</Directory> and <Location ...>...</Location> blocks
        block_regex = /<(Directory|Location)\s+[^>]+>(.*?)<\/\1>/m
        content.scan(block_regex).each do |block_type, block_body|
          unless block_body.match?(/^\s*Require\s+/m)
            require_blocks_without_require << "#{block_type} block missing Require:\n#{block_body.strip[0..100]}..."
          end
        end
      end
    end

    describe 'Apache: Allow Appropriate Access to Web Content' do
      it 'should have Require directives in every <Directory> and <Location> block' do
        expect(require_blocks_without_require).to be_empty, "Blocks missing Require directives:\n#{require_blocks_without_require.join("\n\n")}"
      end
    end
  end


  # 10. Restrict Override for the OS Root Directory
  control 'apache-restrict-override-os-root' do
    impact 1.0
    title 'Restrict Override for the OS Root Directory'
    desc 'The Apache Allow OverRide directive and the new Allow OverrideList directive allow for .htaccess files to be used to override much of the configuration, including authentication, handling of document types, auto generated indexes, access control, and options. When the server finds an .htaccess file (as specified by AccessFileName) it needs to know which directives declared in that file can override earlier access information. When this directive is setto None, then .htaccess files are completely ignored. In this case, the server will not even attempt to read .htaccess files in the filesystem. When this directive is set to All, then any directive which has the .htaccess Context is allowed in the .htaccess files.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'While the functionality of htaccess files is sometimes convenient, usage decentralizes the access controls and increases the risk of configurations being changed or viewed inappropriately by an unintended or rogue .htaccess file. Consider also that some of the more common vulnerabilities in web servers and web applications allow the web files to be viewed or to be modified, then it is wise to keep the configuration out of the web server from being placed in.htaccess files.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find a root <Directory> element.
    2. Remove any AllowOverrideList directives found.
    3. Add a single AllowOverride directive if there is none.
    4. Set the value for AllowOverride to None.
    <Directory />. . .AllowOverride None. . .</Directory>
    Default Value:
    The following is the default root directory configuration:<Directory />. . .AllowOverride None. . .</Directory>
    References:
    1. https://httpd.apache.org/docs/2.4/mod/core.html
    #allowoverride
    2. https://httpd.apache.org/docs/2.4/mod/core.html
    #allowoverridelist'
    tag vulnerability_id: 'Apache-010'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Override for the OS Root Directory'
    
    found_root_block = false
    allowoverride_none = false
    has_other_allowoverride = false
    has_allowoverridelist = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find all <Directory ...>...</Directory> blocks
        content.scan(/<Directory\s*\/\s*>(.*?)<\/Directory>/m).each do |block_body|
          found_root_block = true

          # Check for AllowOverride None (and ONLY None)
          allowoverride_none = true if block_body[0].match(/^\s*AllowOverride\s+None\s*$/m)
          # Check for other AllowOverride directives (not None)
          has_other_allowoverride = true if block_body[0].match(/^\s*AllowOverride\s+(?!None\b)[^\n]+/m)
          # Check for any AllowOverrideList directive
          has_allowoverridelist = true if block_body[0].match(/^\s*AllowOverrideList\b/m)
        end
      end
    end

    describe 'Apache: Restrict Override for the OS Root Directory' do
      it 'should have a <Directory /> block' do
        expect(found_root_block).to be true
      end
      it 'should have AllowOverride None (and only None) in <Directory />' do
        expect(allowoverride_none).to be true
      end
      it 'should not have any AllowOverride value except None in <Directory />' do
        expect(has_other_allowoverride).to be false
      end
      it 'should not have AllowOverrideList in <Directory />' do
        expect(has_allowoverridelist).to be false
      end
    end
  end

  # 11. Restrict Override for All Directories
  control 'apache-restrict-override-all' do
    impact 1.0
    title 'Restrict Override for All Directories'
    desc 'The Apache Allow Override directive and the new Allow Override List directive allow for.htaccess files to be used tverride much of the configuration, including authentication, handling of document types, auto generated indexes, access control, and options. When theserver finds an .htaccess file (as specified by AccessFileName) it needs to know which directives declared in that file can override earlier access information. When this directive is setto None, then .htaccess files are completely ignored. In this case, the server will not even attempt to read .htaccess files in the filesystem. When this directive is set to All, then anydirective which has the .htaccess context is allowed in .htaccess files.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: '.htaccess files decentralizes access control and increases the risk of server configuration being changed inappropriately.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find AllowOverride directives.
    2. Set the value for all AllowOverride directives to None.. . .AllowOverride None. . .
    3. Remove any AllowOverrideList directives found.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #allowoverride2. https://httpd.apache.org/docs/2.4/mod/core.html
    #allowoverridelist'
    tag vulnerability_id: 'Apache-011'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Override for All Directories'
    
    allowoverride_not_none = []
    allowoverridelist_found = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find all AllowOverride directives NOT set to None
        content.scan(/^\s*AllowOverride\s+([^\n]+)/).each do |match|
          value = match[0].strip
          allowoverride_not_none << "#{config_file}: AllowOverride #{value}" unless value.casecmp('None').zero?
        end

        # Find any AllowOverrideList directives
        content.scan(/^\s*AllowOverrideList\b.*/).each do |match|
          allowoverridelist_found << "#{config_file}: #{match.strip}"
        end
      end
    end

    describe 'Apache: Restrict Override for All Directories' do
      it 'should have no AllowOverride directives set to anything except None' do
        expect(allowoverride_not_none).to be_empty, "Found non-None AllowOverride directives:\n#{allowoverride_not_none.join("\n")}"
      end
      it 'should have no AllowOverrideList directives' do
        expect(allowoverridelist_found).to be_empty, "Found AllowOverrideList directives:\n#{allowoverridelist_found.join("\n")}"
      end
    end
  end


  # 12. Restrict Options for the OS Root Directory
  control 'apache-restrict-options-os-root' do
    impact 1.0
    title 'Restrict Options for the OS Root Directory'
    desc 'The Apache Options directive allows for specific configuration of options, including executionof CGI, following symbolic links, server side includes, and content negotiation.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The Options directive for the root OS level is used to create a default minimal options policy that allows only the minimal options at the root directory level. Then for specific web sites or portions of the web site, options may be enabled as needed and appropriate. Nptions should be enabled and the value for the Options directive should be None.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find a root <Directory> element.
    2. Add a single Options directive if there is none.
    3. Set the value for Options to None.
    <Directory />. . .Options None. . .</Directory>
    Default Value:
    The default value for the root directorys Option directive is Indexes FollowSymLinks.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #options'
    tag vulnerability_id: 'Apache-012'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Options for the OS Root Directory'
    
    found_root_block = false
    has_options_none = false
    has_other_options = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find all <Directory />...</Directory> blocks
        content.scan(/<Directory\s*\/\s*>(.*?)<\/Directory>/m).each do |block_body|
          found_root_block = true

          # Check for Options None (and ONLY None)
          has_options_none = true if block_body[0].match(/^\s*Options\s+None\s*$/m)
          # Check for other Options directives (not None)
          has_other_options = true if block_body[0].match(/^\s*Options\s+(?!None\b)[^\n]+/m)
        end
      end
    end

    describe 'Apache: Restrict Options for the OS Root Directory' do
      it 'should have a <Directory /> block' do
        expect(found_root_block).to be true
      end
      it 'should have Options None (and only None) in <Directory />' do
        expect(has_options_none).to be true
      end
      it 'should not have any Options value except None in <Directory />' do
        expect(has_other_options).to be false
      end
    end
  end

  # 13. Restrict Options for the Web Root Directory
  control 'apache-restrict-options-web-root' do
    impact 1.0
    title 'Restrict Options for the Web Root Directory'
    desc '"The Apache Options directive allows for specific configuration of options, including:
    • Execution of CGI
    • Following symbolic links
    • Server side includes
    • Content negotiation"'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The Options directive at the web root or document root level also needs to be restricted to theminimal options required. A setting of None is highly recommended, however it is recognized that this level content negotiation may be needed if multiple languages are supported'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find the document root <Directory> element.
    2. Add or modify any existing Options directive to have a value of None or Multiviews, if multiviews are needed.
    <Directory ""/usr/local/apache2/htdocs"">. . .Options None. . .</Directory>
    Default Value:
    The default value for the web root directory Option directive is FollowSymLinks.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #options'
    tag vulnerability_id: 'Apache-013'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Options for the Web Root Directory'
    
    found_root_block = false
    options_none_or_multiviews = false
    has_other_options = false

    DOCUMENT_ROOTS = [
      '/var/www/html',
      '/usr/local/apache2/htdocs', # add others if needed
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        DOCUMENT_ROOTS.each do |webroot|
          content.scan(/<Directory\s*#{Regexp.escape(webroot)}\s*>(.*?)<\/Directory>/m).each do |block_body|
            found_root_block = true

            # Check for Options None or Options None Multiviews (allow Multiviews if needed)
            if block_body[0].match(/^\s*Options\s+None(\s+Multiviews)?\s*$/m)
              options_none_or_multiviews = true
            end
            # Check for Options directives with other values
            if block_body[0].match(/^\s*Options\s+(?!None(\s+Multiviews)?\s*$)[^\n]+/m)
              has_other_options = true
            end
          end
        end
      end
    end

    describe 'Apache: Restrict Options for the Web Root Directory' do
      it 'should have a <Directory> block for the document root' do
        expect(found_root_block).to be true
      end
      it 'should have Options None (or Options None Multiviews) in the document root block' do
        expect(options_none_or_multiviews).to be true
      end
      it 'should not have any other Options value in the document root block' do
        expect(has_other_options).to be false
      end
    end
  end

  # 14. Minimize Options for Other Directories
  control 'apache-minimize-options-other-dirs' do
    impact 1.0
    title 'Minimize Options for Other Directories'
    desc 'The Apache Options directive allows for specific configuration of options, including execution of CGI, following symbolic links, server side includes, and content negotiation.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Likewise, the options for other directories and hosts needs to be restricted to the minimal optionsrequired. A setting of None is recommended, however it is recognized that other options may beneeded in some cases:
    • Multiviews - Is appropriate if content negotiation is required, such as when multiplelanguages are supported.
    • ExecCGI - Is only appropriate for special directories dedicated to executable content suchas a cgi-bin/ directory. That way you will know what is executed on the server. It ispossible to enable CGI script execution based on file extension or permission settings,however this makes script control and management almost impossible as developers mayinstall scripts without your knowledge. This may become a factor in a hostingenvironment.
    • FollowSymLinks & SymLinksIfOwnerMatch - The following of symbolic links is notrecommended and should be disabled if possible. The usage of symbolic links opens upadditional risk for possible attacks that may use inappropriate symbolic links to accesscontent outside of the document root of the web server. Also consider that it could becombined with a vulnerability that allowed an attacker or insider to create aninappropriate link. The option SymLinksIfOwnerMatch is much safer in that theownership must match in order for the link to be used, however keep in mind there isadditional overhead created by requiring Apache to check the ownership.
    • Includes & IncludesNOEXEC - The IncludesNOEXEC option should only be neededwhen server side includes are required. The full Includes option should not be used as italso allows execution of arbitrary shell commands. See Apache Mod Include for details https://httpd.apache.org/docs/2.4/mod/mod_include.html
    • Indexes - The Indexes option causes automatic generation of indexes, if the defaultindex page is missing, and should be disabled unless required.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files (httpd.conf and any included configuration files)to find all <Directory> elements.
    2. Add or modify any existing Options directive to NOT have a value of Includes. Other options may be set if necessary and appropriate as described above.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #options'
    tag vulnerability_id: 'Apache-014'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Minimize Options for Other Directories'
    
    dirs_with_includes = []

    # You may want to exclude the OS root and web root if you check them elsewhere
    EXCLUDED_DIRS = [
      '/',                 # OS root
      '/var/www/html',     # Web root (adjust as needed)
      '/usr/local/apache2/htdocs'
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find all <Directory ...>...</Directory> blocks
        content.scan(/<Directory\s+([^>]+)>(.*?)<\/Directory>/m).each do |dir, block_body|
          next if EXCLUDED_DIRS.include?(dir.strip)
          # Find any Options directive in this block
          block_body.scan(/^\s*Options\s+([^\n]+)/i).each do |opts|
            dirs_with_includes << dir.strip if opts[0].downcase.include?('includes')
          end
        end
      end
    end

    describe 'Apache: Minimize Options for Other Directories' do
      it 'should not have Options Includes in any <Directory> block other than OS/web root' do
        expect(dirs_with_includes).to be_empty, "Directories with Options Includes:\n#{dirs_with_includes.join("\n")}"
      end
    end
  end

  # 15. Remove Default HTML Content
  control 'apache-remove-default-html' do
    impact 1.0
    title 'Remove Default HTML Content'
    desc 'Apache installations have default content that is not needed or appropriate for production use.The primary function for this sample content is to provide a default web site, provide user manuals or to demonstrate special features of the web server. All content that is not needed should be removed.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Historically these sample content and features have been remotely exploited and can providedifferent levels of access to the server. In the Microsoft arena, Code Red exploited a problemwith the index service provided by the Internet Information Service. Usually these routines arenot written for production use and consequently little thought was given to security in their development.'
    tag remediation: 'Review all pre-installed content and remove content which is not required. In particular look forthe unnecessary content which may be found in the document root directory, a configurationdirectory such as conf/extra directory, or as a Unix/Linux package
    1. Remove the default index.html or welcome page if it is a separate package. If the defaultwelcome page is part of the main Apache httpd package such as it is on Red Hat Linux,then comment out the configuration as shown below. Removing a file such as thewelcome.conf is not recommended as it may get replaced if the package is updated.
    #
    # This configuration file enables the default ""Welcome""
    # page if there is no default index page present for
    # the root URL. To disable the Welcome page, comment
    # out all the lines below.
    #
    #
    #<LocationMatch ""^/+$"">
    #
    # Options -Indexes
    #
    # ErrorDocument 403 /error/noindex.html
    #
    #</LocationMatch>
    2. Remove the Apache user manual content or comment out configurations referencing themanual
    # yum erase httpd-manual
    3. Remove or comment out any Server Status handler configuration.
    #
    # Allow server status reports generated by mod_status,
    # with the URL of http://servername/server-status
    # Change the "".example.com"" to match your domain to enable.
    #
    #
    #<Location /server-status>
    #
    # SetHandler server-status
    #
    # Order deny,allow
    #
    # Deny from all
    #
    # Allow from .example.com
    #
    #</Location>
    4. Remove or comment out any Server Information handler configuration.
    #
    # Allow remote server configuration reports, with the URL of
    # http://servername/server-info (requires that mod_info.c be loaded).
    # Change the "".example.com"" to match your domain to enable.
    #
    #
    #<Location /server-info>
    #
    # SetHandler server-info
    #
    # Order deny,allow
    #
    # Deny from all
    #
    # Allow from .example.com
    #
    #</Location>
    5. Remove or comment out any other handler configuration such as perl-status.
    # This will allow remote server configuration reports, with the URL of
    # http://servername/perl-status
    # Change the "".example.com"" to match your domain to enable.
    #
    #
    #<Location /perl-status>
    #
    # SetHandler perl-script
    #
    # PerlResponseHandler Apache2::Status
    #
    # Order deny,allow
    #
    # Deny from all
    #
    # Allow from .example.com
    #
    #</Location>

    Default Value:
    The default source build provides extra content available in the/usr/local/apache2/conf/extra/ directory, but the configuration of most of the extracontent is commented out by default. In particular, the include of conf/extra/proxyhtml.conf is not commented out in the httpd.conf.
    # Server-pool management (MPM specific)
    #Include conf/extra/httpd-mpm.conf
    # Multi-language error messages
    #Include conf/extra/httpd-multilang-errordoc.conf
    # Fancy directory listings
    #Include conf/extra/httpd-autoindex.conf
    # Language settings
    #Include conf/extra/httpd-languages.conf
    # User home directories
    #Include conf/extra/httpd-userdir.conf
    # Real-time infn requests and configuration
    #Include conf/extra/httpd-info.conf
    # Virtual hosts
    #Include conf/extra/httpd-vhosts.conf
    # Local access to the Apache HTTP Server Manual
    #Include conf/extra/httpd-manual.conf
    # Distributed authoring and versioning (WebDAV)
    #Include conf/extra/httpd-dav.conf
    # Various default settings
    #Include conf/extra/httpd-default.conf
    # Configure mod_proxy_html to understand HTML4/XHTML1<IfModule proxy_html_module>Include conf/extra/proxy-html.conf</IfModule>
    # Secure (SSL/TLS) connections
    #Include conf/extra/httpd-ssl.conf Also, the only other default content is a minimal barebones index.html in the document rootwhich contains.<html><body><h1>It works!</h1></body></html>'
    tag vulnerability_id: 'Apache-015'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Remove Default HTML Content'
    
    # List common document root paths
    DOC_ROOTS = [
      '/var/www/html',
      '/usr/local/apache2/htdocs'
    ]

    unwanted_configs = []
    unwanted_files = []

    # Check for default index.html in common document roots
    DOC_ROOTS.each do |docroot|
      unwanted_files << "#{docroot}/index.html" if file("#{docroot}/index.html").exist?
    end

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for unwanted handler configs and includes
        [
          /<Location\s+\/server-status>/i,
          /<Location\s+\/server-info>/i,
          /<Location\s+\/perl-status>/i,
          /Include\s+conf\/extra\/httpd-manual.conf/i,
          /Include\s+conf\/extra\/httpd-info.conf/i,
          /Include\s+conf\/extra\/proxy-html.conf/i,
          /Include\s+conf\/extra\/httpd-default.conf/i,
          /<LocationMatch\s+\^\/\+\$>/i, # welcome page config
        ].each do |pattern|
          unwanted_configs << "#{config_file}: #{pattern}" if content.match?(pattern)
        end
      end
    end

    describe 'Apache: Remove Default HTML Content' do
      it 'should not have default index.html in any document root' do
        expect(unwanted_files).to be_empty, "Found default index.html files: #{unwanted_files.join(', ')}"
      end
      it 'should not have default handler configs or includes in any config file' do
        expect(unwanted_configs).to be_empty, "Found unwanted config references: #{unwanted_configs.join(', ')}"
      end
    end
  end

  # 16. Remove Default CGI Content printenv
  control 'apache-remove-default-cgi-printenv' do
    impact 1.0
    title 'Remove Default CGI Content printenv'
    desc 'Most Web Servers, including Apache installations have default CGI content which is not needed or appropriate for production use. The primary function for these sample programs is to demonstrate the capabilities of the web server. One common default CGI content for Apache installations is the script print env. This script will print back to the requester all of the CGI environment variables which includes many server configuration details and system paths.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'CGI programs have a long history of security bugs and problems associated with improperlyaccepting user-input. Since these programs are often targets of attackers, we need to make surethat there are no unnecessary CGI programs that could potentially be used for maliciouspurposes. Usually these programs are not written for production use and consequently littlethought was given to security in their development. The printenv script in particular willdisclose inappropriate information about the web server including directory paths and detailedversion and configuration information.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Locate cgi-bin files and directories enabled in the Apache configuration via Script,ScriptAlias, ScriptAliasMatch, or ScriptInterpreterSource directives.
    2. Remove the printenvdefault CGI in cgi-bin directory if it is installed.
    # rm $APACHE_PREFIX/cgi-bin/printenv
    Default Value:
    The default source installation includes the printenv script. However, this script is notexecutable by default.'
    tag vulnerability_id: 'Apache-016'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Remove Default CGI Content printenv'
    
    cgi_dirs = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find ScriptAlias and ScriptAliasMatch
        content.scan(/^\s*ScriptAlias(?:Match)?\s+\S+\s+(\S+)/).each do |match|
          cgi_dirs << match[0]
        end

        # Find ScriptInterpreterSource (rare, just noted for completeness)
        # Does not directly define a dir, but could be extended if needed
      end
    end

    # Add common default cgi-bin locations if not found in config
    cgi_dirs |= ['/usr/lib/cgi-bin', '/usr/local/apache2/cgi-bin', '/var/www/cgi-bin']

    cgi_dirs.uniq!

    unwanted_files = []
    cgi_dirs.each do |dir|
      unwanted_files << "#{dir}/printenv" if file("#{dir}/printenv").exist?
    end

    describe 'Apache: Remove Default CGI Content printenv' do
      it 'should not have printenv in any enabled cgi-bin directory' do
        expect(unwanted_files).to be_empty, "Found printenv in: #{unwanted_files.join(', ')}"
      end
    end
  end

  # 17. Remove Default CGI Content test-cgi
  control 'apache-remove-default-cgi-testcgi' do
    impact 1.0
    title 'Remove Default CGI Content test-cgi'
    desc 'Most Web Servers, including Apache installations have default CGI content which is not needed or appropriate for production use. The primary function for these sample programs is to demonstrate the capabilities of the web server. A common default CGI content for Apache installations is the script test-cgi. This script will print back to the requester CGI environment variables which includes many server configuration details.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'CGI programs have a long history of security bugs and problems associated with improperlyaccepting user-input. Since these programs are often targets of attackers, we need to make surethat there are no unnecessary CGI programs that could potentially be used for maliciouspurposes. Usually these programs are not written for production use and consequently littlethought was given to security in their development. The test-cgi script in particular willdisclose inappropriate information about the web server including directory paths and detailedversion and configuration information.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Locate cgi-bin files and directories enabled in the Apache configuration via Script,ScriptAlias, ScriptAliasMatch, or ScriptInterpreterSource directives.
    2. Remove the test-cgi default CGI in cgi-bin directory if it is installed.
    # rm $APACHE_PREFIX/cgi-bin/test-cgi
    Default Value:
    The default source installation includes the test-cgi script. However, this script is not executableby default.'
    tag vulnerability_id: 'Apache-017'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Remove Default CGI Content test-cgi'
    
    cgi_dirs = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find ScriptAlias and ScriptAliasMatch directives (captures target directory)
        content.scan(/^\s*ScriptAlias(?:Match)?\s+\S+\s+(\S+)/).each do |match|
          cgi_dirs << match[0]
        end

        # Optionally, add logic for Script and ScriptInterpreterSource if needed
      end
    end

    # Add common default CGI locations for completeness
    cgi_dirs |= ['/usr/lib/cgi-bin', '/usr/local/apache2/cgi-bin', '/var/www/cgi-bin']

    cgi_dirs.uniq!

    unwanted_files = []
    cgi_dirs.each do |dir|
      unwanted_files << "#{dir}/test-cgi" if file("#{dir}/test-cgi").exist?
    end

    describe 'Apache: Remove Default CGI Content test-cgi' do
      it 'should not have test-cgi in any enabled cgi-bin directory' do
        expect(unwanted_files).to be_empty, "Found test-cgi in: #{unwanted_files.join(', ')}"
      end
    end
  end

  # 18. Limit HTTP Request Methods
  control 'apache-limit-http-methods' do
    impact 1.0
    title 'Limit HTTP Request Methods'
    desc 'Use the Apache  <LimitExcept>  directive to restrict unnecessary HTTP request methods of the web server tnly accept and process the GET, HEAD, POST and OPTIONS HTTP request methods.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The HTTP 1.1 protocol supports several request methods which are rarely used and potentiallyhigh risk. For example, methods such as PUT and DELETE are rarely used and should be disabledin keeping with the primary security principal of minimize features and options. Also since theusage of these methods is typically to modify resources on the web server, they should beexplicitly disallowed. For normal web server operation, you will typically need to allow only theGET, HEAD and POST request methods. This will allow for downloading of web pages andsubmitting information to web forms. The OPTIONS request method will also be allowed as itused to request which HTTP request methods are allowed. Unfortunately, the Apache<LimitExcept> directive does not deny the TRACE request method. The TRACE request methodwill be disallowed in another benchmark recommendation with the TraceEnable directive.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Locate the Apache configuration files and included configuration files.
    2. Search for the directive on the document root directory such as:
    <Directory ""/usr/local/apache2/htdocs"">. . .</Directory>
    3. Add a directive as shown below within the group of document root directives.
    # Limit HTTP methods to standard methods. 
    Note: Does not limit TRACE<LimitExcept GET POST OPTIONS>Require all denied</LimitExcept>
    4. Search for other directives in the Apache configuration files other than the OS rootdirectory and add the same directives to each. It is very important to understand that thedirectives are based on the OS file system hierarchy as accessed by Apache and not thehierarchy of the locations within web site URLs.
    <Directory ""/usr/local/apache2/cgi-bin"">. . .
    # Limit HTTP methods<LimitExcept GET POST OPTIONS>Require all denied</LimitExcept></Directory>
    Default Value:
    No Limits on HTTP methods.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #limitexcept2. https://www.ietf.org/rfc/rfc2616.txt'
    tag vulnerability_id: 'Apache-018'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Limit HTTP Request Methods'
    
    missing_limitexcept = []

    # List of directories to check (add or adjust as needed for your environment)
    RELEVANT_DIRS = [
      '/usr/local/apache2/htdocs',
      '/var/www/html',
      '/usr/lib/cgi-bin',
      '/usr/local/apache2/cgi-bin',
      '/var/www/cgi-bin'
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        RELEVANT_DIRS.each do |dir|
          # Find <Directory ...>...</Directory> blocks for relevant dirs
          content.scan(/<Directory\s*#{Regexp.escape(dir)}\s*>(.*?)<\/Directory>/m).each do |dir_block|
            block = dir_block[0]
            # Look for <LimitExcept GET POST OPTIONS> or <LimitExcept GET POST>
            if block =~ /<LimitExcept\s+GET\s+POST(\s+OPTIONS)?\s*>(.*?)<\/LimitExcept>/m
              limitexcept_body = $2
              unless limitexcept_body.include?('Require all denied')
                missing_limitexcept << "#{config_file}: <Directory #{dir}> block missing 'Require all denied' in <LimitExcept>"
              end
            else
              missing_limitexcept << "#{config_file}: <Directory #{dir}> block missing <LimitExcept GET POST OPTIONS> (or GET POST)"
            end
          end
        end
      end
    end

    describe 'Apache: Limit HTTP Request Methods' do
      it 'should have <LimitExcept GET POST OPTIONS>Require all denied</LimitExcept> in every relevant <Directory> block' do
        expect(missing_limitexcept).to be_empty, "Missing or incomplete LimitExcept blocks:\n#{missing_limitexcept.join("\n")}"
      end
    end
  end

  # 19. Restrict HTTP Protocol Versions
  control 'apache-restrict-http-protocol' do
    impact 1.0
    title 'Restrict HTTP Protocol Versions'
    desc 'The Apache modules mod_rewrite or mod_security can be used to disallow old and invalid HTTP protocols versions. The HTTP version 1.1 RFC is dated June 1999 and has been supportedby Apache since version 1.2. It should no longer be necessary to allow ancient versions of HTTP such as 1.0 and prior.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Many malicious automated programs, vulnerability scanners and fingerprinting tools will sendabnormal HTTP protocol versions to see how the web server responds. These requests areusually part of the attackers enumeration process and therefore it is important that we respond by denying these requests.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Load the mod_rewrite module for Apache by doing either one of the following:
    a. Build Apache with mod_rewrite statically loaded during the build, by addingthe --enable-rewrite option to the ./configure script.
    ./configure --enable-rewrite.
    b. Or, dynamically loading the module with the LoadModule directive inthe httpd.conf configuration file.
    LoadModule rewrite_module modules/mod_rewrite.so
    2. Locate the main Apache configuration file such as httpd.conf and add the following'
    tag vulnerability_id: 'Apache-019'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict HTTP Protocol Versions'
    
    found_rewrite_module = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                  .map(&:strip)
                                  .reject { |line| line.empty? || line.start_with?('#') }

        if content_lines.any? { |line| line.match?(/^LoadModule\s+rewrite_module\b/) }
          found_rewrite_module = true
          break
        end
      end
    end

    describe 'Apache: Restrict HTTP Protocol Versions' do
      it 'should have mod_rewrite enabled via LoadModule in at least one config file' do
        expect(found_rewrite_module).to be true
      end
    end
  end

  # 20. Restrict Access to .ht* files
  control 'apache-restrict-ht-files' do
    impact 1.0
    title 'Restrict Access to .ht* files'
    desc 'Restrict access to any files beginning with .ht using the Files Match directive.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The default name for access filename which allows files in web directories tverride theApache configuration is .htaccess. The usage of access files should not be allowed, but as adefense in depth a FilesMatch directive is recommended to prevent web clients from viewingthose files in case they are created. Also a common name for web password and group files are.htpasswd and .htgroup. Neither of these files should be placed in the document root, but, inthe event they are, the FilesMatch directive can be used to prevent them from being viewed byweb clients.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the following lines in the Apache configuration file at the server configuration
    <FilesMatch ""^\.ht"">Require all denied</FilesMatch>
    Default Value:
    .ht* files are not accessible.'
    tag vulnerability_id: 'Apache-020'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Access to .ht* files'
    
    found_ht_restriction = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content.lines
                                           .reject { |line| line.strip.start_with?('#') }
                                           .join
        
        if content.match?(/<FilesMatch\s+"?\^\\?\.ht"?\s*>(.*?)Require all denied(.*?)<\/FilesMatch>/m)
          found_ht_restriction = true
          break
        end
      end
    end
    
    describe 'Apache: Restrict Access to .ht* files' do
      it 'should have FilesMatch for .ht* files with Require all denied in at least one config file' do
        expect(found_ht_restriction).to be true
      end
    end
  end

  # 21. Restrict File Extensions
  control 'apache-restrict-file-extensions' do
    impact 1.0
    title 'Restrict File Extensions'
    desc 'Restrict access to inappropriate file extensions that are not expected to be a legitimate part of web sites using the Files Match directive.'

    # Custom tags for report generation
    tag risk_rating: 'High'
    tag severity: 'High'
    tag impact_description: 'There are many files that are often left within the web server document root that could providean attacker with sensitive information. Most often these files are mistakenly left behind after installation, trouble-shooting, or backing up files before editing. Regardless of the reason fortheir creation, these files can still be served by Apache even when there is no hyperlink pointing to them. The web administrators should use the Files Match directive to restrict access to only those file extensions that are appropriate for the web server. Rather than create a list ofpotentially inappropriate file extensions such as .bak, .config, .old, etc, it is recommendedinstead that a white list of the appropriate and expected file extensions for the web server becreated, reviewed and restricted with a FilesMatch directive.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Compile a list of existing file extension on the web server. The following find/awkcommand may be useful, but is likely to need some customization according to theappropriate webroot directories for your web server. Please note that the find commandskips over any files without a dot (.) in the file name, as these are not expected to beappropriate web content.find */htdocs -type f -name "*.*" | awk -F. "{print 
    $NF }" | sort -u
    2. Review the list of existing file extensions, for appropriate content for the web server,remove those that are inappropriate and add any additional file extensions expected to beadded to the web server in the near future.
    3. Add the FilesMatch directive below which denies access to all files by default.
    # Block all files by default, unless specifically allowed.<FilesMatch ""^.*$"">Require all denied</FilesMatch>
    4. Add another a FilesMatch directive that allows access to those file extensionsspecifically allowed from the review process in step 2. An example FilesMatch directiveis below. The file extensions in the regular expression should match your approved list,and not necessarily the expression below.
    # Allow files with specifically approved file extensions
    # Such as (css, htm; html; js; pdf; txt; xml; xsl; ...),
    # images (gif; ico; jpeg; jpg; png; ...), multimedia<FilesMatch ""^.*\.(css|html?|js|pdf|txt|xml|xsl|gif|ico|jpe?g|png)$"">Require all granted</FilesMatch>
    Default Value:
    There are no restrictions on file extensions in the default configuration.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #filesmatch'
    tag vulnerability_id: 'Apache-021'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict File Extensions'
    
    found_deny_all = false
    found_allowlist = false
    allowlist_pattern = '^.*\.(css|html?|js|pdf|txt|xml|xsl|gif|ico|jpe?g|png)$' # Customize as needed!

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Block all by default
        if content.match?(/<FilesMatch\s+"?\^.\*\$"?\s*>\s*Require all denied\s*<\/FilesMatch>/m)
          found_deny_all = true
        end

        # Allow only approved extensions
        if content.match?(/<FilesMatch\s+"?#{allowlist_pattern}"?\s*>\s*Require all granted\s*<\/FilesMatch>/m)
          found_allowlist = true
        end
      end
    end

    describe 'Apache: Restrict File Extensions' do
      it 'should block all files by default' do
        expect(found_deny_all).to be true
      end
      it 'should have an allowlist for approved file extensions' do
        expect(found_allowlist).to be true
      end
    end
  end

  # 22. Deny IP Address Based Requests
  control 'apache-deny-ip-requests' do
    impact 1.0
    title 'Deny IP Address Based Requests'
    desc 'The Apache module mod_rewrite can be used to disallow access for requests that use an IPaddress instead of a host name for the URL. Most normal access to the website from browsers and automated software will use a host name which will therefore include the host name in the HTTP HOST header.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'A common malware propagation and automated network scanning technique is to use IP addresses rather than host names for web requests, since it is much simpler to automate. By denying IP based web requests, these automated techniques will be denied access to the website. Of course, malicious web scanning techniques continue to evolve, and many are now using hostnames, however denying access to the IP based requests is still a worth while defense.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Load the mod_rewrite module for Apache by doing either one of the following:
    a. Build Apache with mod_rewrite statically loaded during the build, by addingthe --enable-rewrite option to the ./configure script.
    ./configure --enable-rewriteb.
    Or, dynamically loading the module with the LoadModule directive inthe httpd.conf configuration file.
    LoadModule rewrite_module modules/mod_rewrite.so
    2. Add the RewriteEngine directive to the configuration within the global server contextwith the value of on so that the rewrite engine is enabled.RewriteEngine On
    3. Locate the Apache configuration file such as httpd.conf and add the following rewrite'
    tag vulnerability_id: 'Apache-022'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Deny IP Address Based Requests'
    
    found_rewrite_module = false
    found_rewrite_rule = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for LoadModule rewrite_module (dynamic load)
        found_rewrite_module ||= !!content.match(/^\s*LoadModule\s+rewrite_module/)

        # Find "RewriteEngine On" (anywhere, uncommented)
        found_rewrite_engine = !!content.match(/^\s*RewriteEngine\s+On/i)

        # Look for a RewriteCond for HTTP_HOST with IPv4 regex, immediately followed by RewriteRule [F]
        content.scan(/RewriteCond\s+%{HTTP_HOST}\s+\^\d+\\\.\d+\\\.\d+\\\.\d+\$\s*\n\s*RewriteRule\s+\^\s+-\s+\[F\]/m) do |_|
          found_rewrite_rule = true
        end
      end
    end

    describe 'Apache: Deny IP Address Based Requests' do
      it 'should have mod_rewrite loaded (or built-in)' do
        expect(found_rewrite_module).to be true
      end
      it 'should have RewriteCond+RewriteRule to deny IP-based Host requests' do
        expect(found_rewrite_rule).to be true
      end
    end
  end

  # 23. Restrict Listen Directive
  control 'apache-restrict-listen' do
    impact 1.0
    title 'Restrict Listen Directive'
    desc 'The Apache Listen directive specifies the IP addresses and port numbers the Apache web serverwill listen for requests. Rather than be unrestricted to listen on all IP addresses available to thesystem, the specific IP address or addresses intended should be explicitly specified. Specifically,a Listen directive with no IP address specified, or with an IP address of zeros should not beused.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Having multiple interfaces on web servers is fairly common, and without explicit Listendirectives, the web server is likely to be listening on an inappropriate IP address / interface that was not intended for the web server. Single homed system with a single IP addressed are also required to have an explicit IP address in the Listen directive, in case additional interfaces areadded to the system at a later date.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Find any Listen directives in the Apache configuration file with no IP address specified,or with an IP address of all zeros similar to the examples below. Keep in mind there maybe both IPv4 and IPv6 addresses on the system.
    Listen 80Listen 0.0.0.0:80
    Listen [::ffff:0.0.0.0]:80
    2. Modify the Listen directives in the Apache configuration file to have explicit IPaddresses according to the intended usage. Multiple Listen directives may be specifiedfor each IP address & Port.
    Listen 10.1.2.3:80
    Listen 192.168.4.5:80
    Listen [2001:db8::a00:20ff:fea7:ccea]:80
    Default Value:
    Listen 80
    References:1. https://httpd.apache.org/docs/2.4/mod/mpm_common.html
    #listen'
    tag vulnerability_id: 'Apache-023'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Listen Directive'
    
    bad_listens = []
    good_listen_found = false

    ipv4_pattern = /^\s*Listen\s+\d{1,3}(?:\.\d{1,3}){3}:(80|443|8080|8081)\s*$/
    ipv6_pattern = /^\s*Listen\s+\[[a-fA-F0-9:]+\]:(80|443|8080|8081)\s*$/

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file_lines = file(config_file).content.lines.map(&:strip).reject { |l| l.empty? || l.start_with?('#') }

        file_lines.each do |line|
          if line.match(/^Listen\s+80$/) ||
             line.match(/^Listen\s+0\.0\.0\.0:(80|443|8080|8081)$/) ||
             line.match(/^Listen\s+\[::\]:(80|443|8080|8081)$/) ||
             line.match(/^Listen\s+\[::ffff:0\.0\.0\.0\]:(80|443|8080|8081)$/)
            bad_listens << "#{config_file}: #{line}"
          elsif line.match(ipv4_pattern) || line.match(ipv6_pattern)
            good_listen_found = true
          end
        end
      end
    end

    describe 'Apache: Restrict Listen Directive' do
      it 'should NOT have generic Listen directives (Listen 80, 0.0.0.0, ::, or ::ffff:0.0.0.0)' do
        expect(bad_listens).to be_empty, "Found insecure Listen directives:\n#{bad_listens.join("\n")}"
      end
      it 'should have at least one explicit IP-bound Listen directive' do
        expect(good_listen_found).to be true
      end
    end
  end

  # 24. Configure the Error Log
  control 'apache-configure-error-log' do
    impact 1.0
    title 'Configure the Error Log'
    desc 'The Log Level directive is used to configure the severity level for the error logs. While theError Log directive configures the error log file name. The log level values are the standardsyslog levels of emerg, alert, crit, error, warn, notice, info and debug. The recommendedlevel is notice for most modules, so that all errors from the emerg level through notice levelwill be logged. The recommended setting for the core module is info so that any not foundrequests will be included in the error logs.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The server error logs are invaluable because they can also be used to spot any potential problemsbefore they become serious. Most importantly, they can be used to watch for anomalous behavior such as a lot of not found or unauthorized errors may be an indication that an attack ispending or has occurred. Starting with Apache 2.4 the error log does not include the not found errors except at the info logging level. Therefore, it is important that the log level be set to infofor the core module. The not found requests need to be included in the error log for both forensics investigation and host intrusion detection purposes. Monitoring the access logs may notbe practical for many web servers with high volume traffic.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Add or modify the LogLevel in the Apache configuration to have a value of info or lower for the core module and notice or lower for all other modules. Note that is it is
    compliant to have a value of info or debug if there is a need for a more verbose log and the storage and monitoring processes are capable of handling the extra load. The
    recommended value is notice core:info.
    LogLevel notice core:info
    2. Add an ErrorLog directive if not already configured. The file path may be relative or absolute, or the logs may be configured to be sent to a syslog server.
    ErrorLog ""logs/error_log""
    3. Add a similar ErrorLog directive for each virtual host configured if the virtual host will have different people responsible for the web site. Each responsible individual or
    organization needs access to their own web logs and needs the skills/training/tools for monitoring the logs.
    Default Value:
    The following is the default configuration:
    LogLevel warn
    ErrorLog ""logs/error_log""
    References:
    1. https://httpd.apache.org/docs/2.4/logs.html
    2. https://httpd.apache.org/docs/2.4/mod/core.html#loglevel
    3. https://httpd.apache.org/docs/2.4/mod/core.html#errorlog'
    tag vulnerability_id: 'Apache-024'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Configure the Error Log'
    
    found_global_error_log = false
    found_global_loglevel = false
    found_vhost_error_log = []
    found_vhost_loglevel = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for global ErrorLog and LogLevel
        found_global_error_log ||= !!content.match(/^\s*ErrorLog\s+/)
        found_global_loglevel ||= !!content.match(/^\s*LogLevel\s+(notice core:info|info|debug)/)

        # Check for ErrorLog and LogLevel in each <VirtualHost> block
        content.scan(/<VirtualHost\b[^>]*>(.*?)<\/VirtualHost>/m).each do |block_body|
          vhost_has_errorlog = block_body[0].match(/^\s*ErrorLog\s+/)
          vhost_has_loglevel = block_body[0].match(/^\s*LogLevel\s+(notice core:info|info|debug)/)
          found_vhost_error_log << config_file if vhost_has_errorlog
          found_vhost_loglevel << config_file if vhost_has_loglevel
        end
      end
    end

    describe 'Apache: Configure the Error Log' do
      it 'should have a global ErrorLog directive' do
        expect(found_global_error_log).to be true
      end
      it 'should have a global LogLevel set to at least notice core:info, info, or debug' do
        expect(found_global_loglevel).to be true
      end
      it 'should have an ErrorLog in every VirtualHost block (if any)' do
        expect(found_vhost_error_log).to_not be_empty
      end
      it 'should have a LogLevel in every VirtualHost block (if any)' do
        expect(found_vhost_loglevel).to_not be_empty
      end
    end
  end

  # 25. Configure a Syslog Facility for Error Logging
  control 'apache-syslog-error-logging' do
    impact 1.0
    title 'Configure a Syslog Facility for Error Logging'
    desc 'The Error Log directive should be configured to send logs to a syslog facility so that the logscan be processed and monitored along with the system logs.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'It is easy for the web server error logs to be overlooked in the log monitoring process, and yet the application level attacks have become the most common and are extremely important for detecting attacks early, as well as detecting non-malicious problems such as a broken link, orinternal errors. By including the Apache error logs with the system logging facility, the application logs are more likely to be included in the established log monitoring process.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Add an ErrorLog directive if not already configured. Any appropriate syslog facility maybe used in place of local
    1.ErrorLog ""syslog:local1""
    2. Add a similar ErrorLog directive for each virtual host if necessary.
    Default Value:
    The following is the default configuration:ErrorLog ""logs/error_log""
    References:1. https://httpd.apache.org/docs/2.4/logs.html'
    tag vulnerability_id: 'Apache-025'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Configure a Syslog Facility for Error Logging'
    
    found_syslog_global = false
    vhosts_without_syslog = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for global ErrorLog using syslog
        found_syslog_global ||= !!content.match(/^\s*ErrorLog\s+"?syslog:(local[0-7]|daemon|user)"?/)

        # Check in each VirtualHost block
        content.scan(/<VirtualHost\b[^>]*>(.*?)<\/VirtualHost>/m).each do |block_body|
          unless block_body[0].match(/^\s*ErrorLog\s+"?syslog:(local[0-7]|daemon|user)"?/)
            vhosts_without_syslog << config_file
          end
        end
      end
    end

    describe 'Apache: Configure a Syslog Facility for Error Logging' do
      it 'should have at least one global ErrorLog using syslog facility' do
        expect(found_syslog_global).to be true
      end
      it 'should have ErrorLog using syslog in every VirtualHost block (if any)' do
        expect(vhosts_without_syslog).to be_empty, "VirtualHosts missing syslog ErrorLog: #{vhosts_without_syslog.uniq.join(', ')}"
      end
    end
  end

  # 26. Configure the Access Log
  control 'apache-configure-access-log' do
    impact 1.0
    title 'Configure the Access Log'
    desc 'The Log Format directive defines the format and information to be included in the access log entries. The Custom Log directive specifies the log file, syslog facility or piped logging utility.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The server access logs are also invaluable for a variety of reasons. They can be used to determinewhat resources are being used most. Most importantly, they can be used to investigate anomalous behavior that may be an indication that an attack is pending or has occurred. If the server onlylogs errors, and does not log successful access, then it is very difficult to investigate incidents. You may see that the errors stop, and wonder if the attacker gave up, or was the attack successful.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Add or modify the LogFormat directives in the Apache configuration to use the standardand recommended combined format show as shown below.
    LogFormat ""%h %l %u %t \""%r\"" %>s %b \""%{Referer}i\"" \""%{Useragent}i\"""" combined
    2. Add or modify the CustomLog directives in the Apache configuration to use thecombined format with an appropriate log file, syslog facility or piped logging utility.
    CustomLog log/access_log combined
    3. Add a similar CustomLog directives for each virtual host configured if the virtual hostwill have different people responsible for the web site. Each responsible individual ororganization needs access to their own web logs as well as the skills/training/tools formonitoring the logs.
    The format string tokens provide the following information:
    o %h = Remote hostname or IP address if HostnameLookups is set to Off, which isthe default.o %l =Remote logname / identity.o %u =Remote user, 
    if the request was authenticated.o %t = Time the request was received,o %r = First line of request.o %>s = Final status.o %b = Size of response in bytes.o %{Referer}i = Variable value for Referer header.o %{User-agent}i = Variable value for User Agent header.
    Default Value:
    The following are the default log configuration:LogFormat ""%h %l %u %t \""%r\"" %>s %b \""%{Referer}i\"" \""%{User-Agent}i\""combinedLogFormat ""%h %l %u %t \""%r\"" %>s %b"" commonCustomLog ""logs/access_log"" common
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
    #customlog2. https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
    #formats'
    tag vulnerability_id: 'Apache-026'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Configure the Access Log'
    
    combined_logformat = false
    customlog_combined_global = false
    vhosts_without_combined_log = []

    # Common combined log format string (allow for whitespace differences)
    combined_format_regex = /LogFormat\s+"?%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User.?Agent}i\\"" combined/i

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        combined_logformat ||= !!content.match(combined_format_regex)
        customlog_combined_global ||= !!content.match(/^\s*CustomLog\s+\S+\s+combined/i)

        # Check each <VirtualHost> block for CustomLog ... combined
        content.scan(/<VirtualHost\b[^>]*>(.*?)<\/VirtualHost>/m).each do |block_body|
          unless block_body[0].match(/^\s*CustomLog\s+\S+\s+combined/i)
            vhosts_without_combined_log << config_file
          end
        end
      end
    end

    describe 'Apache: Configure the Access Log' do
      it 'should have a LogFormat directive defining the combined format' do
        expect(combined_logformat).to be true
      end
      it 'should have a global CustomLog using the combined format' do
        expect(customlog_combined_global).to be true
      end
      it 'should have a CustomLog using the combined format in every VirtualHost' do
        expect(vhosts_without_combined_log).to be_empty
      end
    end
  end

  # 27. Log Storage and Rotation
  control 'apache-log-rotation' do
    impact 1.0
    title 'Log Storage and Rotation'
    desc 'It is important that there is adequate disk space on the partition that will hold all the log files, and that log rotation is configured to retain at least 3 months or 13 weeks if central logging is notused for storage.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Keep in mind that the generation of logs is under a potential attackers control. So, do not holdany Apache log files on the root partition of the OS. This could result in a denial of service against your web server host by filling up the root partition and causing the system to crash. For this reason, it is recommended that the log files should be stored on a dedicated partition.Likewise consider that attackers sometimes put information into your logs which is intended toattack your log collection or log analysis processing software. So, it is important that they are not vulnerable. Investigation of incidents often require access to several months or more of logs,which is why it is important to keep at least 3 months available. Two common log rotation utilities include rotatelogs(8) which is bundled with Apache, and logrotate(8) commonly bundled on Linux distributions are described in the remediation section.'
    tag remediation: 'To implement the recommended state, do either option a if using the Linux logrotate utility oroption b if using a piped logging utility such as the Apache rotatelogs:a) File Logging with Logrotate:
    1. Add or modify the web log rotation configuration to match your configured log files in/etc/logrotate.d/httpd to be similar to the following./var/log/httpd/*log {missingoknotifemptysharedscriptspostrotate/bin/kill -HUP "cat /var/run/httpd.pid 2>/dev/null" 2> /dev/null|| trueendscript}
    2. Modify the rotation period and number of logs to keep so that at least 13 weeks or 3months of logs are retained. This may be done as the default value for all logs in/etc/logrotate.conf or in the web specific log rotation configuration in/etc/logrotate.d/httpdto be similar to the following.
    # rotate log files weeklyweekly
    # keep 13 weeks of backlogsrotate 13
    3. For each virtual host configured with its own log files ensure that those log files are alsoincluded in a similar log rotation.b) Piped Logging:
    1. Configure the log rotation interval and log file names to a suitable interval such as daily.CustomLog ""|bin/rotatelogs -l /var/logs/logfile.%Y.%m.%d 86400""combined
    2. Ensure the log file naming and any rotation scripts provide for retaining at least 3 months or 13 weeks of log files.
    3. For each virtual host configured with its own log files ensure that those log files are alsoincluded in a similar log rotation.
    Default Value:
    The following is the default httpd log rotation configuration in /etc/logrotate.d/httpd:/var/log/httpd/*log {missingoknotifemptysharedscriptspostrotate/bin/kill -HUP "cat /var/run/httpd.pid 2>/dev/null" 2> /dev/null || trueendscript}The default log retention configured in /etc/logrotate.conf:
    # rotate log files weeklyweekly
    # keep 4 weeks worth of backlogsrotate 4'
    tag vulnerability_id: 'Apache-027'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Log Storage and Rotation'
    
    found_rotatelogs = false
    rotatelogs_long_enough = false
    logrotate_found = false
    logrotate_long_enough = false

    # Check Apache config for rotatelogs
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Look for rotatelogs usage
        content.scan(/rotatelogs\s+[^ ]+\s+(\d+)/i).each do |match|
          found_rotatelogs = true
          # 86400 seconds = 1 day, so 13 weeks = 13 * 7 = 91 days = 91 logs minimum
          # If using rotatelogs, you must check log file naming and external retention script, not just rotation period
          rotatelogs_long_enough = true if match[0].to_i <= 86400
        end
      end
    end

    # Check for logrotate configuration
    if file('/etc/logrotate.d/httpd').exist? || file('/etc/logrotate.conf').exist?
      logrotate_found = true
      logrotate_conf_files = [
        '/etc/logrotate.d/httpd',
        '/etc/logrotate.conf'
      ].select { |f| file(f).exist? }

      logrotate_conf_files.each do |conf|
        content = file(conf).content
        if content.match(/rotate\s+1[3-9]/) || content.match(/rotate\s+[2-9][0-9]+/)
          logrotate_long_enough = true
        end
      end
    end

    describe 'Apache: Log Storage and Rotation' do
      it 'should have log rotation (rotatelogs or logrotate) configured' do
        expect(found_rotatelogs || logrotate_found).to be true
      end
      it 'should retain at least 13 weeks of logs' do
        expect(rotatelogs_long_enough || logrotate_long_enough).to be true
      end
    end
  end

  # 28. Install mod_ssl and/or mod_nss
  control 'apache-install-ssl-module' do
    impact 1.0
    title 'Install mod_ssl and/or mod_nss'
    desc 'Secure Sockets Layer (SSL) was developed by Netscape and turned into an open standard andwas renamed Transport Layer Security (TLS) as part of the process. TLS is important forprotecting communication and can provide authentication of the server and even the client.However contrary to vendor claims, implementing SSL does NOT directly make your web servermore secure! SSL is used to encrypt traffic and therefore does provide confidentiality of privateinformation and users credentials. Keep in mind, however that just because you have encryptedthe data in transit does not mean that the data provided by the client is secure while it is on theserver. Also, SSL does not protect the web server, as attackers will easily target SSL-Enabledweb servers, and the attack will be hidden in the encrypted channel. The mod_ssl module is thestandard, most used module that implements SSL/TLS for Apache. A newer module found on Red Hat systems can be a compliment or replacement for mod_ssl and provides the samefunctionality plus additional security services. The mod_nss is an Apache moduleimplementation of the Network Security Services (NSS) software from Mozilla, whichimplements a wide range of cryptographic functions in addition to TLS.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'It is best to plan for SSL/TLS implementation from the beginning of any new web server. Asmost web servers have some need for SSL/TLS due to:• Non-public information submitted that should be protected as it is transmitted to the webserver.
    • Non-public information that is downloaded from the web server.
    • Users are going to be authenticated to some portion of the web server
    • There is a need to authenticate the web server to ensure users that they have reached thereal web server and have not been phished or redirected to a bogus site.'
    tag remediation: 'Perform either of the following to implement the recommended state:
    1. For Apache installations built from the source, use the option --with-ssl= to specify theopenssl path, and the --enable-ssl configure option to add the SSL modules to thebuild. The --with-included-apr configure option may be necessary if there areconflicts with the platform version. If a new version of Openssl is needed it may bedownloaded from http://www.openssl.org/ See the Apache documentation on buildingfrom source http://httpd.apache.org/docs/2.4/install.htmlfor details.
    # ./configure --with-included-apr --with-ssl=
    $OPENSSL_DIR --enable-ssl
    2. For installations using OS packages, it is typically just a matter of ensuring the mod_sslpackage is installed. The mod_nsspackage might also be installed. The following yumcommands are suitable for Red Hat Linux.
    # yum install mod_ssl
    Default Value:
    SSL is not enabled by default.
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html2. https://www.centos.org/docs/5/html/5.4/technical-notes/mod_nss.html'
    tag vulnerability_id: 'Apache-028'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Install mod_ssl and/or mod_nss'
    
    found_ssl_module = false
    package_installed = false

    # Check config for module loaded
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
          .map(&:strip)
          .reject { |line| line.empty? || line.start_with?('#') }
        if content_lines.any? { |line| line.match?(/^LoadModule (ssl_module|nss_module)/) }
          found_ssl_module = true
          break
        end
      end
    end

    # Check for mod_ssl or mod_nss package (for OS package installs)
    if ['redhat', 'centos', 'fedora'].include?(os.name)
      package_installed = package('mod_ssl').installed? || package('mod_nss').installed?
    elsif ['debian', 'ubuntu'].include?(os.name)
      package_installed = package('libapache2-mod-ssl').installed? || package('libapache2-mod-nss').installed?
    end

    describe 'Apache: Install mod_ssl and/or mod_nss' do
      it 'should have mod_ssl or mod_nss package installed (if using OS packages)' do
        expect(package_installed).to be true
      end
      it 'should include ssl_module or nss_module in at least one config file' do
        expect(found_ssl_module).to be true
      end
    end
  end


  # 29. Ensure All Web Content is Accessed via HTTPS
  control 'apache-https-only' do
    impact 1.0
    title 'Ensure All Web Content is Accessed via HTTPS'
    desc 'All of the website content should be served via HTTPS rather than HTTP. A redirect from the HTTP website to the HTTPS content is often useful and is recommended, but all significant content should be accessed via HTTPS so that it is authenticated and encrypted.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The usage of clear text HTTP prevents the client browser from authenticating the
    connection and ensuring the integrity of the website information. Without the HTTPS
    authentication, a client may be subjected to a variety of man-in-the-middle and spoofing
    attacks which would cause them to receive modified web content which could harm the
    organization’s reputation. Through DNS attacks or malicious redirects, the client could
    arrive at a malicious website instead of the intended website. The malicious website could
    deliver malware, request credentials, or deliver false information.'
    tag remediation: 'Perform the following to implement the recommended state:
    Move the web content to a TLS enabled website, and add an HTTP Redirect directive to the
    Apache configuration file to redirect to the TLS enabled website similar to the example
    shown.
    Redirect permanent / https://www.cisecurity.org/'
    tag vulnerability_id: 'Apache-029'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure All Web Content is Accessed via HTTPS'
    
    http_hosts_missing_redirect = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Find <VirtualHost *:80> or <VirtualHost [ip]:80> blocks
        content.scan(/<VirtualHost\s+[^>]*:80[^>]*>(.*?)<\/VirtualHost>/m).each do |block_body|
          block = block_body[0]
          # Look for permanent HTTPS redirect
          has_redirect = !!block.match(/^\s*Redirect\s+permanent\s+\/\s+https:\/\//)
          # Alternatively, look for RewriteRule/RewriteCond for HTTPS upgrade
          has_rewrite = block.match(/^\s*RewriteEngine\s+On/m) &&
                        block.match(/^\s*RewriteCond\s+%{HTTPS}\s+off/m) &&
                        block.match(/^\s*RewriteRule\s+.*https:\/\/.*\[R=301,L\]/m)
          http_hosts_missing_redirect << "Missing HTTPS redirect in config #{config_file}" unless has_redirect || has_rewrite
        end
      end
    end

    describe 'Apache: Ensure All Web Content is Accessed via HTTPS' do
      it 'should have a permanent HTTPS redirect (or equivalent) in every HTTP VirtualHost' do
        expect(http_hosts_missing_redirect).to be_empty, "Missing redirect in: #{http_hosts_missing_redirect.join(', ')}"
      end
    end
  end

  # 30. Set TimeOut to 10 or less
  control 'apache-timeout' do
    impact 1.0
    title 'Set TimeOut to 10 or less'
    desc 'Denial of Service (DoS) is an attack technique with the intent of preventing a web site fromserving normal user activity. DoS attacks, which are normally applied to the network layer, arealso possible at the application layer. These malicious attacks can succeed by starving a systemof critical resources, vulnerability exploit, or abuse of functionality. Although there is no 100%solution for preventing DoS attacks, the following recommendation uses the Timeout directiveto mitigate some of the risk, by requiring more effort for a successful DoS attack. Of course, DoSattacks can happen in rather unintentional ways as well as intentional and these directives willhelp in many of those situations as well.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'One common technique for DoS is to initiate many connections to the server. By decreasing thetimeout for old connections and we allow the server to free up resources more quickly and bemore responsive. By making the server more efficient, it will be more resilient to DoSconditions. The Timeout directive affects several timeout values for Apache, so review theApache document carefully. http://httpd.apache.org/docs/2.4/mod/core.html#timeout'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the Timeout directive in the Apache configuration to have a value of 10 secondsor shorter.
    Timeout 10
    Default Value:
    Timeout 60
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #timeoutNotes:'
    tag vulnerability_id: 'Apache-030'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set TimeOut to 10 or less'
    
    bad_timeouts = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^TimeOut\s+(\d+)$/
            value = $1.to_i
            bad_timeouts << "#{config_file}:#{idx+1}:#{l}" if value > 10
          end
        end
      end
    end

    describe 'Apache: Set TimeOut to 10 or less' do
      it 'should not include any TimeOut greater than 10 in any config file' do
        expect(bad_timeouts).to be_empty, "Found TimeOut > 10: #{bad_timeouts.join(', ')}"
      end
    end
  end

  # 31. Set the KeepAlive directive to On
  control 'apache-keepalive-on' do
    impact 1.0
    title 'Set the KeepAlive directive to On'
    desc 'The KeepAlive directive controls whether Apache will reuse the same TCP connection per clientto process subsequent HTTP requests from that client. It is recommended that the KeepAlivedirective be set to On.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Allowing per-client reuse of TCP sockets reduces the amount of system and network resourcesrequired to serve requests. This efficiency gain may improve a servers resiliency to DoS attacks.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the KeepAlive directive in the Apache configuration to have a value of On, sothat KeepAlive connections are enabled.
    KeepAlive On
    Default Value:
    KeepAlive On
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #keepaliveNotes:'
    tag vulnerability_id: 'Apache-031'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the KeepAlive directive to On'
    
    found_keepalive_on = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^KeepAlive On/) }
          found_keepalive_on = true
          break
        end
      end
    end
    
    describe 'Apache: Set the KeepAlive directive to On' do
      it 'should include KeepAlive On in at least one config file' do
        expect(found_keepalive_on).to be true
      end
    end
  end

  # 32. Set MaxKeepAliveRequests to 100 or greater
  control 'apache-max-keepalive-requests' do
    impact 1.0
    title 'Set MaxKeepAliveRequests to 100 or greater'
    desc 'The MaxKeepAliveRequests directive limits the number of requests allowed per connectionwhen KeepAlive is on. If it is set to 0, unlimited requests will be allowed.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The MaxKeepAliveRequests directive is important to be used to mitigate the risk of Denial ofService (DoS) attack technique by reducing the overhead imposed on the server. The KeepAlivedirective must be enabled before it is effective. Enabling KeepAlives allows for multiple HTTPrequests to be sent while keeping the same TCP connection alive. This reduces the overhead ofhaving to setup and tear down TCP connections for each request. By making the server moreefficient, it will be more resilient to DoS conditions.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the MaxKeepAliveRequests directive in the Apache configuration to have avalue of 100 or more.
    MaxKeepAliveRequests 100
    Default Value:
    MaxKeepAliveRequests 100
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #maxkeepaliverequests'
    tag vulnerability_id: 'Apache-032'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set MaxKeepAliveRequests to 100 or greater'
    
    found_max_keepalive = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^MaxKeepAliveRequests\s+(100|[1-9][0-9]{2,})$/) }
          found_max_keepalive = true
          break
        end
      end
    end
    
    describe 'Apache: Set MaxKeepAliveRequests to 100 or greater' do
      it 'should include MaxKeepAliveRequests 100 or greater in at least one config file' do
        expect(found_max_keepalive).to be true
      end
    end
  end

  # 33. Set KeepAliveTimeout Low to Mitigate Denial of Service
  control 'apache-keepalive-timeout' do
    impact 1.0
    title 'Set KeepAliveTimeout Low to Mitigate Denial of Service'
    desc 'The KeepAliveTimeout directive specifies the number of seconds Apache will wait for asubsequent request before closing a connection that is being kept alive.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The KeepAliveTimeout directive is used mitigate some of the risk, by requiring more effort fora successful DoS attack. By enabling KeepAlive and keeping the timeout relatively low for oldconnections and we allow the server to free up resources more quickly and be more responsive.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the KeepAliveTimeout directive in the Apache configuration to have a value of15 or less.
    KeepAliveTimeout 15
    Default Value:
    KeepAliveTimeout 5
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #keepalivetimeout'
    tag vulnerability_id: 'Apache-033'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set KeepAliveTimeout Low to Mitigate Denial of Service'
    
    found_keepalive_timeout = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^KeepAliveTimeout\s+(1[0-5]|[1-9])$/) }
          found_keepalive_timeout = true
          break
        end
      end
    end
    
    describe 'Apache: Set KeepAliveTimeout Low to Mitigate Denial of Service' do
      it 'should include KeepAliveTimeout 15 or less in at least one config file' do
        expect(found_keepalive_timeout).to be true
      end
    end
  end

  # 34. Set Timeout Limits for Request Headers
  control 'apache-timeout-headers' do
    impact 1.0
    title 'Set Timeout Limits for Request Headers'
    desc 'The RequestReadTimeout directive allows configuration of timeout limits for client requests.The header portion of the directive provides for an initial timeout value, a maximum timeout anda minimum rate. The minimum rate specifies that after the initial timeout, the server will wait anadditional 1 second for each N bytes received. The recommended setting is to have a maximumtimeout of 40 seconds or less. Keep in mind that for SSL/TLS virtual hosts the time for the TLShandshake must fit within the timeout.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Setting a request header timeout is vital for mitigating Denial of Service attacks based on slowrequests. The slow request attacks are particularly lethal and relative easy to perform, becausethey require very little bandwidth and can easily be done through anonymous proxies. Starting inJune 2009 with the Slow Loris DoS attack, which used a slow GET request, was published byRobert Hansen (RSnake) on his blog http://ha.ckers.org/slowloris/. Later in November 2010 atthe OWASP App Sec DC conference Wong Onn Chee demonstrated a slow POST request attackwhich was even more effective. See https://www.owasp.org/index.php/H.....t.....t....p.......p....o....s....t for details.'
    tag remediation: '1. Load the mod_requesttimeout module in the Apache configuration with the followingconfiguration.LoadModule reqtimeout_module modules/mod_reqtimeout.so
    2. Add a RequestReadTimeout directive similar to the one below with the maximumrequest header timeout value of 40 seconds or less.
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
    Default Value:
    header=20-40,MinRate=500
    References:1. http://ha.ckers.org/slowloris/2. https://www.owasp.org/index.php/H.....t.....t....p.......p....o....s....t3. https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html'
    tag vulnerability_id: 'Apache-034'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set Timeout Limits for Request Headers'
    
    found_reqtimeout_module = false
    found_header_limit = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for LoadModule for mod_reqtimeout
        found_reqtimeout_module ||= !!content.match(/^\s*LoadModule\s+reqtimeout_module/)

        # Find RequestReadTimeout header=... with max 40 or less
        content.scan(/^\s*RequestReadTimeout\s+([^\n]+)/).each do |line|
          params = line[0]
          if params.match(/header=(\d+)-(\d+)/)
            min, max = params.match(/header=(\d+)-(\d+)/).captures.map(&:to_i)
            found_header_limit ||= (max <= 40)
          elsif params.match(/header=(\d+)/)
            single = params.match(/header=(\d+)/)[1].to_i
            found_header_limit ||= (single <= 40)
          end
        end
      end
    end

    describe 'Apache: Set Timeout Limits for Request Headers' do
      it 'should have mod_reqtimeout loaded' do
        expect(found_reqtimeout_module).to be true
      end
      it 'should have RequestReadTimeout header timeout max 40 or less' do
        expect(found_header_limit).to be true
      end
    end
  end

  # 35. Set the LimitRequestLine directive to 512 or less
  control 'apache-limit-request-line' do
    impact 1.0
    title 'Set the LimitRequestLine directive to 512 or less'
    desc 'Buffer Overflow attacks attempt to exploit an application by providing more data than theapplication buffer can contain. If the application allows copying data to the buffer tverflowthe boundaries of the buffer, then the application is vulnerable to a buffer overflow. The resultsof Buffer overflow vulnerabilities vary, and may result in the application crashing, or may allowthe attacker to execute instructions provided in the data. The Apache LimitRequest* directivesallow the Apache web server to limit the sizes of requests and request fields and can be used tohelp protect programs and applications processing those requests. Specifically, theLimitRequestLine directive limits the allowed size of a clients HTTP request-line, whichconsists of the HTTP method, URI, and protocol version.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The limiting of the size of request line is helpful so that the web server can prevent anunexpectedly long or large request from being passed to a potentially vulnerable CGI program,module or application that would have attempted to process the request. Of course, theunderlying dependency is that we need to set the limits high enough to not interfere with any oneapplication on the server, while setting them low enough to be of value in protecting theapplications. Since the configuration directive is available only at the server configuration level,it is not possible to tune the value for different portions of the same web server. Please read theApache documentation carefully, as these requests may interfere with the expected functionalityof some web applications.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the LimitRequestline directive in the Apache configuration to have a value of512 or shorter.
    LimitRequestline 512
    Default Value:
    LimitRequestline 8190
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #limitrequestline'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the LimitRequestLine directive to 512 or less'
    tag vulnerability_id: 'Apache-035'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the LimitRequestLine directive to 512 or less'
    
    found_limit_request_line = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LimitRequestLine\s+([1-9][0-9]{0,2}|[1-4][0-9]{3}|50[0-9]|51[0-2])$/) }
          found_limit_request_line = true
          break
        end
      end
    end
    
    describe 'Apache: Set the LimitRequestLine directive to 512 or less' do
      it 'should include LimitRequestLine 512 or less in at least one config file' do
        expect(found_limit_request_line).to be true
      end
    end
  end

  # 36. Set the LimitRequestFields directive to 100 or less
  control 'apache-limit-request-fields' do
    impact 1.0
    title 'Set the LimitRequestFields directive to 100 or less'
    desc 'The LimitRequestFields directive limits the number of fields allowed in an HTTP request.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The limiting of the number of fields is helpful so that the web server can prevent anunexpectedly high number of fields from being passed to a potentially vulnerable CGI program,module or application that would have attempted to process the request. Of course, theunderlying dependency is that we need to set the limits high enough to not interfere with any oneapplication on the server, while setting them low enough to be of value in protecting theapplications. Since the configuration directives are available only at the server configurationlevel, it is not possible to tune the value for different portions of the same web server. Please readthe Apache documentation carefully, as these requests may interfere with the expectedfunctionality of some web applications.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the LimitRequestFields directive in the Apache configuration to have a valueof 100 or less. If the directive is not present the default depends on a compile time configuration,but defaults to a value of 100.
    LimitRequestFields 100
    Default Value:
    LimitRequestFields 100
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #limitrequestfields'
    tag vulnerability_id: 'Apache-036'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the LimitRequestFields directive to 100 or less'
    
    found_limit_request_fields = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LimitRequestFields\s+(100|\d|\d\d)$/) }
          found_limit_request_fields = true
          break
        end
      end
    end
    
    describe 'Apache: Set the LimitRequestFields directive to 100 or less' do
      it 'should include LimitRequestFields 100 or less in at least one config file' do
        expect(found_limit_request_fields).to be true
      end
    end
  end

  # 37. Set the LimitRequestFieldsize directive to 1024 or less
  control 'apache-limit-request-fieldsize' do
    impact 1.0
    title 'Set the LimitRequestFieldsize directive to 1024 or less'
    desc 'The LimitRequestFieldSize limits the number of bytes that will be allowed in an HTTPrequest header. It is recommended that the LimitRequestFieldSize directive be set to 1024 orless.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'By limiting of the size of request headers is helpful so that the web server can prevent anunexpectedly long or large value from being passed to exploit a potentially vulnerable program.Of course, the underlying dependency is that we need to set the limits high enough to notinterfere with any one application on the server, while setting them low enough to be of value inprotecting the applications. Since the configuration directives are available only at the serverconfiguration level, it is not possible to tune the value for different portions of the same webserver. Please read the Apache documentation carefully, as these requests may interfere with theexpected functionality of some web applications.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the LimitRequestFieldsize directive in the Apache configuration to have avalue of 1024 or less.
    LimitRequestFieldsize 1024
    Default Value:
    LimitRequestFieldsize 8190
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #limitrequestfieldsize'
    tag vulnerability_id: 'Apache-037'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the LimitRequestFieldsize directive to 1024 or less'
    
    found_limit_request_fieldsize = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LimitRequestFieldsize\s+(\d|[1-9]\d{1,2}|10[0-1][0-9]|102[0-4])$/) }
          found_limit_request_fieldsize = true
          break
        end
      end
    end
    
    describe 'Apache: Set the LimitRequestFieldsize directive to 1024 or less' do
      it 'should include LimitRequestFieldsize 1024 or less in at least one config file' do
        expect(found_limit_request_fieldsize).to be true
      end
    end
  end

  # 38. Set the LimitRequestBody directive to 102400 or less
  control 'apache-limit-request-body' do
    impact 1.0
    title 'Set the LimitRequestBody directive to 102400 or less'
    desc 'The LimitRequestBody directive limits the number of bytes that are allowed in a request body.Size of requests may vary greatly; for example, during a file upload the size of the file must fitwithin this limit.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The limiting of the size of the request body is helpful so that the web server can prevent anunexpectedly long or large request from being passed to a potentially vulnerable program. Ofcourse, the underlying dependency is that we need to set the limits high enough to not interferewith any one application on the server, while setting them low enough to be of value inprotecting the applications. The LimitRequestBody may be configured on a per directory, or perlocation context. Please read the Apache documentation carefully, as these requests may interfere with the expected functionality of some web applications.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the LimitRequestBody directive in the Apache configuration to have a value of102400 (100K) or less. Please read the Apache documentation so that it is understood that thisdirective will limit the size of file up-loads to the web server.
    LimitRequestBody 102400
    Default Value:
    LimitRequestBody 0 (unlimited)
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #limitrequestbody'
    tag vulnerability_id: 'Apache-038'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set the LimitRequestBody directive to 102400 or less'
    
    found_limit_request_body = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LimitRequestBody\s+(\d|[1-9]\d{1,4}|[1-9]\d{2,3}|102[0-3][0-9]|10240[0-0])$/) }
          found_limit_request_body = true
          break
        end
      end
    end
    
    describe 'Apache: Set the LimitRequestBody directive to 102400 or less' do
      it 'should include LimitRequestBody 102400 or less in at least one config file' do
        expect(found_limit_request_body).to be true
      end
    end
  end

  # 39. Ensure Access to .git Files Is Restricted
  control 'apache-restrict-git-files' do
    impact 1.0
    title 'Ensure Access to .git Files Is Restricted'
    desc 'Restrict access to any files beginning with .git using the FilesMatch directive.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'More and more websites track their changes in a Git repository we see a lot of attackers search for .git directories. Access to .git directories should be restricted. These files should be placed in the document root, but, in the event they are, the FilesMatch directive can be used to prevent them from being viewed by web clients.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the following lines in the Apache configuration file at the server 
    configuration level.
    <DirectoryMatch ""/\.git"">
    Require all denied
    </DirectoryMatch>
    Default Value:
    This is not set by default
    References:
    1. https://httpd.apache.org/docs/2.4/mod/core.html#filesmatch'
    tag vulnerability_id: 'Apache-039'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure Access to .git Files Is Restricted'
    
    found_git_restriction = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content.lines
                                           .reject { |line| line.strip.start_with?('#') }
                                           .join
        
        if content.match?(/<DirectoryMatch\s+["']?\\?\/\.git["']?\s*>\s*Require all denied\s*<\/DirectoryMatch>/im)
          found_git_restriction = true
          break
        end
      end
    end
    
    describe 'Apache: Ensure Access to .git Files Is Restricted' do
      it 'should have DirectoryMatch for .git directories with Require all denied in at least one config file' do
        expect(found_git_restriction).to be true
      end
    end
  end

  # 40. Ensure Access to .svn Files Is Restricted
  control 'apache-restrict-svn-files' do
    impact 1.0
    title 'Ensure Access to .svn Files Is Restricted'
    desc 'Restrict access to any files beginning with .svn using the FilesMatch directive.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'More and more websites track their changes in a SVN repository we see a lot of attackers search for .svn directories. Access to .svn directories should be restricted. These files should be placed in the document root, but, in the event they are, the FilesMatch directive can be used to prevent them from being viewed by web clients.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the following lines in the Apache configuration file at the server configuration level.
    <DirectoryMatch ""/\.snv"">
    Require all denied
    </DirectoryMatch>
    Default Value:
    This is not set by default
    References:
    1. https://httpd.apache.org/docs/2.4/mod/core.html#filesmatch'
    tag vulnerability_id: 'Apache-040'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure Access to .svn Files Is Restricted'
    
    found_svn_restriction = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content.lines
                                           .reject { |line| line.strip.start_with?('#') }
                                           .join
        
        if content.match?(/<DirectoryMatch\s+["']?\\?\/\.svn["']?\s*>\s*Require all denied\s*<\/DirectoryMatch>/im)
          found_svn_restriction = true
          break
        end
      end
    end
    
    describe 'Apache: Ensure Access to .svn Files Is Restricted' do
      it 'should have DirectoryMatch for .svn directories with Require all denied in at least one config file' do
        expect(found_svn_restriction).to be true
      end
    end
  end

  # 41. Ensure the Basic and Digest Authentication Modules are Disabled
  control 'apache-disable-auth-modules' do
    impact 1.0
    title 'Ensure the Basic and Digest Authentication Modules are Disabled'
    desc 'The Apache mod_auth_basic and mod_auth_digest modules support HTTP Basic Authentication and HTTP Digest Authentication respectively. The two authentication protocols are used to restrict access to users who provide a valid user name and password.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Neither HTTP Basic nor HTTP Digest authentication should be used as the protocols are out dated and no longer considered secure. Disabling the modules will improve the security posture of the web server by reducing the amount of potentially vulnerable code paths exposed to the network and reducing potential for unauthorized access to files via misconfigured access controls. In the early days of the web, Basic HTTP Authentication was considered adequate if it was only used over HTTPS, so that the credentials would not be sent in the clear. Basic authentication uses Base64 to encode the credentials which are sent with every request. Base64 encoding is of course easily reversed, and is no more secure than clear text. The issues with using Basic Auth over HTTPS is that it does not meet current security standards for protecting the login credentials and protecting the authenticated session. The following security issues plague the Basic Authentication protocol.
    • The authenticated session has an indefinite length (as long as any browser window is open) and is not timed-out on the server when the session is idle. 
    • Application logout is required to invalidate the session on the server to limit, but in the case of Basic Authentication, there is no server-side session that can be invalidated. 
    • The credentials are remembered by the browser and stored in memory. 
    • There is no way to disable auto-complete, where the browser offers to store the passwords. Passwords stored in the browser can be accessed if the client system or browser become compromised. 
    • The credentials are more likely to be exposed since they are automatically sent with every request. 
    • Administrators may at times have access to the HTTP headers sent in request for the purposes of diagnosing problems and detecting attacks. Having a users credentials in the clear in the HTTP headers, may allow a user to repudiate actions performed, because the web or system administrators also had access to the users password. The HTTP Digest Authentication is considered even worse than Basic Authentication because it stores the password in the clear on the server, and has the same session management issues as Basic Authentication.'
    tag remediation: 'Perform either one of the following to disable the HTTP Basic or HTTP Digest
    authentication modules:
    1. For source builds with static modules run the Apache ./configure script without including the mod_auth_basic, and mod_auth_digest in the --enablemodules=configure script options.
    $ cd $DOWNLOAD_HTTPD
    $ ./configure
    2. For dynamically loaded modules comment out or remove the LoadModule directive for mod_auth_basic, and mod_auth_digest modules from the httpd.conf file.
    ##LoadModule mod_auth_basic modules/mod_auth_basic.so
    ##LoadModule mod_auth_digest modules/mod_auth_digest.so
    Default Value:
    The mod_auth_basic and mod_auth_digest modules are not enabled with a default source build.
    References:
    1. https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html
    2. https://httpd.apache.org/docs/2.4/mod/mod_auth_digest.html'
    tag vulnerability_id: 'Apache-041'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure the Basic and Digest Authentication Modules are Disabled'
    
    found_basic_auth = false
    found_digest_auth = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^LoadModule auth_basic_module/) }
          found_basic_auth = true
        end
        
        if content_lines.any? { |line| line.match?(/^LoadModule auth_digest_module/) }
          found_digest_auth = true
        end
      end
    end
    
    describe 'Apache: Ensure the Basic and Digest Authentication Modules are Disabled' do
      it 'should not include auth_basic_module in any config file' do
        expect(found_basic_auth).to be false
      end
      it 'should not include auth_digest_module in any config file' do
        expect(found_digest_auth).to be false
      end
    end
  end

  # 42. Disable HTTP TRACE Method
  control 'apache-disable-trace' do
    impact 1.0
    title 'Disable HTTP TRACE Method'
    desc 'Use the Apache TraceEnable directive to disable the HTTP TRACE request method.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The HTTP 1.1 protocol requires support for the TRACE request method which reflects the requestback as a response and was intended for diagnostics purposes. The TRACE method is not neededand is easily subjected to abuse and should be disabled.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Locate the main Apache configuration file such as httpd.conf.
    2. Add a TraceEnable directive to the server level configuration with a value of off. Server level configuration is the top-level configuration, not nested within any other
    directives like <Directory> or <Location>.'
    tag vulnerability_id: 'Apache-042'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable HTTP TRACE Method'
    
    found_trace_disabled = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^TraceEnable\s+Off/) }
          found_trace_disabled = true
          break
        end
      end
    end
    
    describe 'Apache: Disable HTTP TRACE Method' do
      it 'should include TraceEnable Off in at least one config file' do
        expect(found_trace_disabled).to be true
      end
    end
  end

  # 43. Restrict Browser Frame Options
  control 'apache-restrict-frame-options' do
    impact 1.0
    title 'Restrict Browser Frame Options'
    desc 'The Header directive allows server HTTP response headers to be added, replaced or merged. We will use the directive to add a server HTTP response header to tell browsers to restrict all of the web pages from being framed by other web sites.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Using iframes and regular web frames to embed malicious content along with expected webcontent has been a favored attack vector for attacking web clients for a long time. This canhappen when the attacker lures the victim to a malicious web site, which using frames to includethe expected content from the legitimate site. The attack can also be performed via XSS (eitherreflected, DOM or stored XSS) to add the malicious content to the legitimate web site. Tocombat this vector, an HTTP Response header, X-Frame-Options, has been introduced that allows a server to specify whether a web page may be loaded in any frame (DENY) or thoseframes that share the pages origin (SAMEORIGIN).'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the Header directive for the X-Frames-Options header in the Apacheconfiguration to have the condition always, an action of append and a value of SAMEORIGIN orDENY, as shown below.Header always append X-Frame-Options SAMEORIGIN
    Default Value:
    The X-Frame-Options HTTP response header is not generated by default.
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_headers.html#header2. https://developer.mozilla.org/en/The_X-FRAME-OPTIONS_response_header/3. https://blogs.msdn.com/b/ie/archive/2009/01/27/ie8-security-part-vii-clickjackingdefenses.aspx'
    tag vulnerability_id: 'Apache-043'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Browser Frame Options'
    
    found_frame_options = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
          .map(&:strip)
          .reject { |line| line.empty? || line.start_with?('#') }

        # Accept "append" (preferred) or "set"
        if content_lines.any? { |line| line.match(/^Header\s+always\s+(append|set)\s+X-Frame-Options\s+(SAMEORIGIN|DENY)$/i) }
          found_frame_options = true
          break
        end
      end
    end

    describe 'Apache: Restrict Browser Frame Options' do
      it 'should include X-Frame-Options SAMEORIGIN or DENY in at least one config file using Header always append or set' do
        expect(found_frame_options).to be true
      end
    end
  end

  # 44. Enable HTTP Strict Transport Security
  control 'apache-hsts' do
    impact 1.0
    title 'Enable HTTP Strict Transport Security'
    desc 'HTTP Strict Transport Security (HSTS) is an optional web server security policy mechanismspecified by an HTTP Server header. The HSTS header allows a server declaration that only HTTPS communication should be used rather than clear text HTTP communication.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Usage of HTTP Strict Transport Security (HSTS) helps protect HSTS compliant browsers andother agents from HTTP downgrade attacks. Downgrade attacks include a variety of man-in-themiddleattacks which leave the web communication vulnerable to disclosure and modification byforcing the usage of HTTP rather than HTTPS communication. The sslstrip attack tool byMoxie Marlinspike released in 2009 is one such attack, which works when the server allows bothHTTP and HTTPS communication. However, a man-in-the-middle HTTP-to-HTTPS proxywould be effective in cases where the server required HTTPS, but did not publish an HSTSpolicy to the browser. This attack would also be effective on browsers which were not compliantwith HSTS. All current up-to-date browsers support HSTS.The HSTS header specifies a length of time in seconds that the browser / user agent shouldaccess the server only using HTTPS. The header may also specify if all sub-domains should alsobe included in the same policy. Once a compliant browser receives the HSTS Header it will notallow access to the server via HTTP. Therefore, it is important that you ensure that there is noportion of the web site or web application that requires HTTP prior to enabling the HSTSprotocol.If all sub-domains are to be included via the includeSubDomains option, then carefully considerall various host names, web applications and third-party services used to include any DNSCNAME values that may be impacted. An overly broad includeSubDomains policy will disableaccess to HTTP web sites for all websites with the same domain name. Also consider that theaccess will be disabled for the number of seconds given in the max-age value, so in the event amistake is made, a large value, such as a year, could create significant support issues. Anoptional flag of preload may be added if the web site name is to be submitted to be preloaded inChrome, Firefox and Safari browsers. See https://hstspreload.appspot.com/ for details.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add a Header directive as shown below in the Apache server level configuration and every virtual host that is SSL enabled. The includeSubDomains and preload flags may be included in the header, but are not required.
    Header always set Strict-Transport-Security ""max-age=600”;
    includeSubDomains; preload
    - or -
    Header always set Strict-Transport-Security ""max-age=600""
    Default Value:
    The Strict Transport Security header is not present by default.
    References:
    1. https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
    2. https://www.owasp.org/index.php/HTTP_Strict_Transport_Security
    3. https://moxie.org/software/sslstrip/
    4. https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
    5. https://hstspreload.appspot.com/'
    tag vulnerability_id: 'Apache-044'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Enable HTTP Strict Transport Security'
    
    found_hsts = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^Header.*always set Strict-Transport-Security.*max-age=600/) }
          found_hsts = true
          break
        end
      end
    end
    
    describe 'Apache: Enable HTTP Strict Transport Security' do
      it 'should include Strict-Transport-Security with max-age=600 in at least one config file' do
        expect(found_hsts).to be true
      end
    end
  end

  # 45. Set ServerToken to 'Prod'
  control 'apache-servertokens-prod' do
    impact 1.0
    title 'Set ServerToken to Prod'
    desc 'Configure the Apache ServerTokens directive to provide minimal information. By setting thevalue to Prod or ProductOnly. The only version information given in the server HTTP responseheader will be Apache rather than providing detailed on modules and versions installed.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Information is power and identifying web server details greatly increases the efficiency of anyattack, as security vulnerabilities are extremely dependent upon specific software versions andconfigurations. Excessive probing and requests may cause too much "noise" being generated andmay tip off an administrator. If an attacker can accurately target their exploits, the chances ofsuccessful compromise prior to detection increase dramatically. Script Kiddies are constantlyscanning the Internet and documenting the version information openly provided by web servers.The purpose of this scanning is to accumulate a database of software installed on those hosts,which can then be used when new vulnerabilities are released.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the ServerTokens directive as shown below to have the value of Prod orProductOnly:
    ServerTokens Prod
    Default Value:
    The default value is Full which provides the most detailed information.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #servertokens'
    tag vulnerability_id: 'Apache-045'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set ServerToken to Prod'
    
    found_server_tokens = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^ServerTokens\s+Prod/) }
          found_server_tokens = true
          break
        end
      end
    end
    
    describe 'Apache: Set ServerToken to Prod' do
      it 'should include ServerTokens Prod in at least one config file' do
        expect(found_server_tokens).to be true
      end
    end
  end

  # 46. Set ServerSignature to 'Off'
  control 'apache-serversignature-off' do
    impact 1.0
    title 'Set ServerSignature to Off'
    desc 'Disable the server signatures which generates a signature line as a trailing footer at the bottom ofserver generated documents such as error pages.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'Server signatures are helpful when the server is acting as a proxy, since it helps the userdistinguish errors from the proxy rather than the destination server, however in this context thereis no need for the additional information and we want to limit leakage of unnecessaryinformation.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the ServerSignature directive as shown below to have the value of Off:
    ServerSignature Off
    Default Value:
    The default value is Off for ServerSignature.
    References:1. https://httpd.apache.org/docs/2.4/mod/core.html
    #serversignature'
    tag vulnerability_id: 'Apache-046'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set ServerSignature to Off'
    
    found_server_signature = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^ServerSignature\s+Off/) }
          found_server_signature = true
          break
        end
      end
    end
    
    describe 'Apache: Set ServerSignature to Off' do
      it 'should include ServerSignature Off in at least one config file' do
        expect(found_server_signature).to be true
      end
    end
  end

  # 47. Information Leakage via Default Apache Content
  control 'apache-info-leak-default-content' do
    impact 1.0
    title 'Information Leakage via Default Apache Content'
    desc 'In previous recommendations, we have removed default content such as the Apache manuals anddefault CGI programs. However, if you want to further restrict information leakage about theweb server, it is important that default content such as icons are not left on the web server.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'To identify the type of web servers and versions software installed it is common for attackers toscan for icons or special content specific to the server type and version. A simple request likehttp://example.com/icons/apache_pb2.png may tell the attacker that the server is Apache 2.4 asshown below. The many icons are used primarily for auto indexing, which is also recommendedto be disabled.'
    tag remediation: 'Perform either of the following to implement the recommended state:
    1. The default source build places the auto-index and icon configurations in theextra/httpd-autoindex.conf file, so it can be disabled by leaving the include linecommented out in the main httpd.conffile as shown below.
    # Fancy directory listings
    #Include conf/extra/httpd-autoindex.conf
    2. Alternatively, the icon alias directive and the directory access control configuration canbe commented out as shown if present:
    # We include the /icons/ alias for FancyIndexed directory listings. If
    # you do not use FancyIndexing, you may comment this out.
    #
    #Alias /icons/ ""/var/www/icons/""
    #<Directory ""/var/www/icons"">
    # Options Indexes MultiViews FollowSymLinks
    # AllowOverride None
    # Order allow,deny
    # Allow from all
    #</Directory>
    Default Value:
    The default source build does not enable access to the Apache icons.'
    tag vulnerability_id: 'Apache-047'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Information Leakage via Default Apache Content'
    
    found_autoindex_include = false
    found_icons_alias = false
    found_icons_directory = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        lines = file(config_file).content.lines.map(&:strip)
        lines.reject { |l| l.empty? || l.start_with?('#') }.each do |line|
          found_autoindex_include ||= line.match?(/^Include\s+conf\/extra\/httpd-autoindex\.conf$/)
          found_icons_alias      ||= line.match?(/^Alias\s+\/icons\//)
          found_icons_directory  ||= line.match?(/^<Directory\s+["']?\/var\/www\/icons["']?>/)
        end
      end
    end

    describe 'Apache: Information Leakage via Default Apache Content' do
      it 'should not include autoindex config' do
        expect(found_autoindex_include).to be false
      end
      it 'should not include /icons/ Alias' do
        expect(found_icons_alias).to be false
      end
      it 'should not include /var/www/icons Directory block' do
        expect(found_icons_directory).to be false
      end
    end
  end

  # 48. Information Leakage via ETag
  control 'apache-info-leak-etag' do
    impact 1.0
    title 'Information Leakage via ETag'
    desc 'The FileETag directive configures the file attributes that are used to create the ETag (entity tag)response header field when the document is based on a static file. The ETag value is used incache management to save network bandwidth. The value returned may be based oncombinations of the file inode, the modification time, and the file size.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'When the FileETag is configured to include the file inode number, remote attackers may beable to discern the inode number from returned values. The inode is considered sensitive information, as it could be useful in assisting in other attacks.'
    tag remediation: 'Perform the following to implement the recommended state:
    Remove all instances of the FileETag directive. Alternatively, add or modify the FileETagdirective in the server and each virtual host configuration to have either the value None or MTimeSize.
    Default Value:
    The default value is MTime Size.
    References:1. http://httpd.apache.org/docs/2.4/mod/core.html
    #FileETag2. https://nvd.nist.gov/vuln/detail/CVE-2003-1418'
    tag vulnerability_id: 'Apache-048'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Information Leakage via ETag'
    
    found_etag = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^FileETag\s+(None|MTimeSize)/) }
          found_etag = true
          break
        end
      end
    end
    
    describe 'Apache: Information Leakage via ETag' do
      it 'should include FileETag None or MTimeSize in at least one config file' do
        expect(found_etag).to be true
      end
    end
  end

  # 49. Ensure HTTP Header Referrer-Policy is set appropriately
  control 'apache-referrer-policy' do
    impact 1.0
    title 'Ensure HTTP Header Referrer-Policy is set appropriately'
    desc 'The server now allows for controlling the amount of "referrer" information being sent  with requests. Limiting information to only what is needed is security best practice.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'You must only limit the header information to what is needed to support the request. Limiting it to much may disrupt the ability to get a proper/expected response.'
    tag remediation: 'Perform the following to implement the recommended state: Add or modify the Header directive for the Referrer-Policy header in the Apache configuration to have the appropriate condition as shown below. Header set Referrer-Policy ""<Directive>""
    Default Value:
    Referrer-Policy Policy is not set by Default
    References:
    1. https://httpd.apache.org/docs/2.4/mod/mod_headers.html#header
    2. https://owasp.org/www-project-cheatsheets/cheatsheets/Content_Security_Policy_Cheat_Sheet
    3. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-SecurityPolicy
    4. https://en.wikipedia.org/wiki/Clickjacking'
    tag vulnerability_id: 'Apache-049'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure HTTP Header Referrer-Policy is set appropriately '
    
    # List of strong policies (adjust as needed for your environment)
    secure_policies = [
      'no-referrer',
      'no-referrer-when-downgrade',
      'strict-origin',
      'strict-origin-when-cross-origin',
      'same-origin'
    ]

    found_secure_policy = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each do |line|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          secure_policies.each do |policy|
            if l =~ /^Header\s+(\w+\s+)?set\s+Referrer-Policy\s+"?#{policy}"?/i
              found_secure_policy = true
              break
            end
          end
        end
      end
    end

    describe 'Apache: Ensure HTTP Header Referrer-Policy is set appropriately' do
      it 'should include a secure Referrer-Policy in at least one config file' do
        expect(found_secure_policy).to be true
      end
    end
  end

  # 50. Install a Valid Trusted Certificate
  control 'apache-valid-cert' do
    impact 1.0
    title 'Install a Valid Trusted Certificate'
    desc 'The default SSL certificate is self-signed and is not trusted. Install a valid certificate signed by acommonly trusted certificate authority. To be valid, the certificate must be:
    • Signed by a trusted certificate authority
    • Not be expired, and
    • Have a common name that matches the host name of the web server, such aswww.example.com.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'A digital certificate on your server automatically communicates your sites authenticity to visitors web browsers. If a trusted authority signs your certificate, it confirms for the visitor theyare actually communicating with you, and not with a fraudulent site stealing credit card numbersor personal information.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Decide on the host name to be used for the certificate. It is important to remember that the browser will compare the host name in the URL to the common name in the
    certificate, so that it is important that all https: URLs match the correct host name.
    Specifically, the host name www.example.com is not the same as example.com nor the same as ssl.example.com.
    2. Generate a private key using openssl. Although certificate key lengths of 1024 have been common in the past, a key length of 2048 is now recommended for strong authentication.
    The key must be kept confidential and will be encrypted with a passphrase by default.
    Follow the steps below and respond to the prompts for a passphrase. See the Apache or
    OpenSSL documentation for details:
    o https://httpd.apache.org/docs/2.4/ssl/ssl_faq.html#realcert
    o https://www.openssl.org/docs/HOWTO/certificates.txt
    # cd /etc/pki/tls/certs
    # umask 077
    # openssl genrsa -aes128 2048 > example.com.key
    Generating RSA private key, 2048 bit long modulus
    ...+++
    ............+++
    e is 65537 (0x10001)
    Enter pass phrase:
    Verifying - Enter pass phrase:
    3. Generate the certificate signing request (CSR) to be signed by a certificate authority. It is important that common name exactly make the web host name.
    # openssl req -utf8 -new -key www.example.com.key -out www.example.com.csr
    Enter pass phrase for example.com.key:
    You are about to be asked to enter information that will be incorporated into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter ".", the field will be left blank.
    -----
    Country Name (2 letter code) [GB]:US
    State or Province Name (full name) [Berkshire]:New York
    Locality Name (eg, city) [Newbury]:Lima
    Organization Name (eg, company) [My Company Ltd]:Durkee Consulting
    Organizational Unit Name (eg, section) []:
    Common Name (eg, your name or your servers hostname) []:www.example.com
    Email Address []:ralph@example.com
    Please enter the following extra attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:
    # mv www.example.com.key /etc/pki/tls/private/
    4. Send the certificate signing request (CSR) to a certificate signing authority to be signed and follow their instructions for submission and validation. The CSR and the final signed
    certificate are just encoded text, and need to be protected for integrity, but not confidentiality. This certificate will be given out for every SSL connection made.
    5. The resulting signed certificate may be named www.example.com.crt and placed in /etc/pki/tls/certs/ as readable by all (mode 0444). Please note that the certificate
    authority does not need the private key (example.com.key) and this file must be carefully protected. With a decrypted copy of the private key, it would be possible to
    decrypt all conversations with the server.
    6. Do not forget the passphrase used to encrypt the private key. It will be required every time the server is started in https mode. If it is necessary to avoid requiring an
    administrator having to type the passphrase every time the httpd service is started, the private key may be stored in clear text. Storing the private key in clear text increases the convenience while increasing the risk of disclosure of the key, but may be appropriate for the sake of being able to restart, if the risks are well managed. Be sure that the key file is only readable by root. To decrypt the private key and store it in clear text file the following openssl command may be used. You can tell by the private key headers
    whether it is encrypted or clear text.
    # cd /etc/pki/tls/private/
    # umask 077
    # openssl rsa -in www.example.com.key -out www.example.com.key.clear
    7. Locate the Apache configuration file for mod_ssl and add or modify the SSLCertificateFile and SSLCertificateKeyFiledirectives to have the correct path for the private key and signed certificate files. If a clear text key is referenced then a passphrase will not be required. You can use the CAs certificate that signed your certificate instead of the CA bundle, to speed up the initial SSL connection as fewer certificates will need to be transmitted.
    SSLCertificateFile /etc/pki/tls/certs/example.com.crt
    SSLCertificateKeyFile /etc/pki/tls/private/example.com.key
    # Default CA file, can be replaced with your CAs certificate.
    SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt
    8. Lastly, start or restart the httpd service and verify correct functioning with your favorite browser.

    References:
    1. https://www.owasp.org/index.php/Testing_for_SSL-TLS_%28OWASP-CM-001%29
    2. https://httpd.apache.org/docs/2.4/ssl/ssl_faq.html#realcert
    3. https://www.openssl.org/docs/HOWTO/certificates.txt'
    tag vulnerability_id: 'Apache-050'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Install a Valid Trusted Certificate'
    
    found_cert_file = false
    found_key_file = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        if content_lines.any? { |line| line.match?(/^SSLCertificateFile/) }
          found_cert_file = true
        end
        
        if content_lines.any? { |line| line.match?(/^SSLCertificateKeyFile/) }
          found_key_file = true
        end
      end
    end
    
    describe 'Apache SSL certificate configuration across all config files' do
      it 'should have SSLCertificateFile set in at least one config file' do
        expect(found_cert_file).to be true
      end
      it 'should have SSLCertificateKeyFile set in at least one config file' do
        expect(found_key_file).to be true
      end
    end
  end

  # 51. Disable the SSL v3.0 Protocol
  control 'apache-disable-ssl3' do
    impact 1.0
    title 'Disable the SSL v3.0 Protocol'
    desc 'The Apache SSL Protocol directive specifies the SSL and TLS protocols allowed. The SSLv3 protocol should be disabled in this directive as it is outdated and vulnerable to information disclosure. Only TLS protocols should be enabled.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The SSLv3 protocol was discovered to be vulnerable to the POODLE attack (Padding Oracle OnDowngraded Legacy Encryption) in October 2014. The attack allows decryption and extraction of information from the servers memory. Due to this vulnerability disabling the SSLv3 protocolis highly recommended.'
    tag remediation: 'Perform the following to implement the recommended state: 
    Search the Apache configuration files for the SSLProtocol directive; add the directive, if not present, or change the value to match one of the following values. The first setting TLSv1.1 TLS1.2 is preferred when it is acceptable to also disable the TLSv1.0 protocol. See the level 2 recommendation ""Disable the TLS v1.0 Protocol"" for details.
    SSLProtocol TLSv1.1 TLSv1.2
    SSLProtocol TLSv1
    Default Value:
    SSLProtocol all
    References:
    1. https://www.us-cert.gov/ncas/alerts/TA14-290A
    2. https://www.openssl.org/~bodo/ssl-poodle.pdf'
    tag vulnerability_id: 'Apache-051'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable the SSL v3.0 Protocol'
    
    found_sslprotocol = false
    bad_sslprotocols = []
    compliant = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLProtocol\s+(.+)$/
            found_sslprotocol = true
            value = $1
            has_ssl3 = value.match?(/\bSSLv3\b/i)
            has_tls10 = value.match?(/\bTLSv1(\s|$)/i)
            has_all = value.match?(/\ball\b/i)
            # Guidance allows: TLSv1.1 TLSv1.2 OR TLSv1
            is_ok = value.strip.match?(/\A(TLSv1\.2(\s+TLSv1\.3)?|\-all\s+\+TLSv1\.2(\s+\+TLSv1\.3)?)\Z/i)
            bad_sslprotocols << "#{config_file}:#{idx+1}:#{l}" if has_ssl3 || has_tls10 || has_all || !is_ok
            compliant ||= is_ok
          end
        end
      end
    end

    describe 'Apache: Disable the SSL v3.0 Protocol' do
      it 'should set SSLProtocol to only secure values (TLSv1.1 and/or TLSv1.2, or TLSv1 as fallback), and not include SSLv3, TLSv1.0, or all' do
        expect(found_sslprotocol).to be true
        expect(bad_sslprotocols).to be_empty, "Found non-compliant SSLProtocol: #{bad_sslprotocols.join(', ')}"
        expect(compliant).to be true
      end
    end
  end

  # 52. Restrict Weak SSL/TLS Ciphers
  control 'apache-restrict-weak-ciphers' do
    impact 1.0
    title 'Restrict Weak SSL/TLS Ciphers'
    desc 'Disable weak SSL ciphers using the SSL Cipher Suite, and SSL Honor CipherOrder directives.The SSL Cipher Suite directive specifies which ciphers are allowed in the negotiation with the client. While the SSL Honor Cipher Order causes the servers preferred ciphers to be used insteadof the clients specified preferences.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The SSL/TLS protocols support a large number of encryption ciphers including many weak ciphers that are subject to man-in-the middle attacks and information disclosure. Some implementations even support the NULL cipher which allows a TLS connection without any encryption! Therefore, it is critical to ensure the configuration only allows strong ciphers greater than or equal to 128-bit to be negotiated with the client. Stronger 256-bit ciphers should beallowed and preferred. In addition, enabling the SSL Honor Cipher Order further protects the client from man-in-the-middle downgrade attacks by ensuring the servers preferred ciphers willbe used rather than the clients preferences.In addition, the RC4 stream ciphers should be disabled, even though they are widely used and have been recommended in previous Apache benchmarks as a means of mitigating attacks based on CBC cipher vulnerabilities. The RC4 ciphers have known cryptographic weaknesses and areno longer recommended. The IETF has published RFC 7465 standard [2] that would disallowRC4 negotiation for all TLS versions. While the document is somewhat new (Feb 2015) it isexpected the RC4 cipher suites will begin to disappear from options in TLS deployments. In themeantime, it is important to ensure that RC4-based cipher suites are disabled in theconfiguration.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the following line in the Apache server level configuration and every virtual host that is SSL enabled:
    SSLHonorCipherOrder On
    SSLCipherSuite ALL:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL
    It is not recommended to add !SSLv3 to the directive even if the SSLv3 protocol is not in use. Doing so disables ALL of the ciphers that may used with SSLv3, which includes the same ciphers used with the TLS protocols. The !aNULL will disable both the ADH and AECDH ciphers, so the !ADH is not required.

    Default Value:
    The following are the default values:
    SSLCipherSuite default depends on OpenSSL version.
    SSLHonorCipherOrder default is Off

    References:
    1. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslciphersuite
    2. https://tools.ietf.org/html/rfc7465
    3. https://community.qualys.com/blogs/securitylabs/2013/03/19/rc4-in-tls-is-broken-nowwhat
    4. https://github.com/rbsec/sslscan'
    tag vulnerability_id: 'Apache-052'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Weak SSL/TLS Ciphers'
    
    bad_honor_cipher_order = []
    bad_cipher_suite = []
    bad_protocol = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check all SSLHonorCipherOrder directives
        content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLHonorCipherOrder\s+(\w+)$/i
            bad_honor_cipher_order << "#{config_file}:#{idx+1}:#{l}" unless $1.downcase == "on"
          end
        end

        # Check all SSLCipherSuite directives
        content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLCipherSuite\s+(.+)$/i
            value = $1
            # Required exclusions
            %w(!EXP !NULL !LOW !SSLv2 !MD5 !RC4 !aNULL).each do |excl|
              bad_cipher_suite << "#{config_file}:#{idx+1}:missing #{excl} in: #{l}" unless value.include?(excl)
            end
            # Should NOT include !SSLv3
            bad_cipher_suite << "#{config_file}:#{idx+1}:should not include !SSLv3: #{l}" if value.include?('!SSLv3')
          end
        end

        # Check all SSLProtocol directives
        content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLProtocol\s+(.+)$/i
            value = $1
            bad_protocol << "#{config_file}:#{idx+1}:#{l}" if value.match?(/\bSSLv2\b|\bSSLv3\b/i)
          end
        end
      end
    end

    describe 'Apache: Restrict Weak SSL/TLS Ciphers' do
      it 'should have SSLHonorCipherOrder On in all config files' do
        expect(bad_honor_cipher_order).to be_empty, "Bad SSLHonorCipherOrder: #{bad_honor_cipher_order.join(', ')}"
      end
      it 'should have SSLCipherSuite with all required ! exclusions and without !SSLv3 in all config files' do
        expect(bad_cipher_suite).to be_empty, "Bad SSLCipherSuite: #{bad_cipher_suite.join(', ')}"
      end
      it 'should not have SSLProtocol enabling SSLv2 or SSLv3 in any config file' do
        expect(bad_protocol).to be_empty, "Bad SSLProtocol: #{bad_protocol.join(', ')}"
      end
    end
  end

  # 53. Disable SSL Insecure Renegotiation
  control 'apache-disable-insecure-reneg' do
    impact 1.0
    title 'Disable SSL Insecure Renegotiation'
    desc 'A man-in-the-middle renegotiation attack was discovered in SSLv3 and TLSv1 in November,2009 (CVE-2009-3555). First, a work around and then a fix was approved as an InternetStandard as RFC 574, Feb 2010. The work around, which removes the renegotiation, is availablefrom OpenSSL as of version 0.9.8l and newer versions. For details:https://www.openssl.org/news/secadv_20091111.txt The SSLInsecureRenegotiation directivewas added in Apache 2.2.15, for web servers linked with OpenSSL version 0.9.8m or later, toprovide backward compatibility to clients with the older, unpatched SSL implementations.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Enabling the SSL Insecure Renegotiation directive leaves the server vulnerable to man-in-the middle renegotiation attack. Therefore, the SSL Insecure Renegotiation directive should not been abled.'
    tag remediation: 'Perform the following to implement the recommended state:
    Search the Apache configuration files for the SSLInsecureRenegotiation directive. If thedirective is present modify the value to be off. If the directive is not present then no action isrequired.SSLInsecureRenegotiation off
    Default Value:
    SSLInsecureRenegotiation off
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html
    #sslinsecurerenegotiation 2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2009-35553. https://azure.microsoft.com/en-us/services/multi-factor-authentication/'
    tag vulnerability_id: 'Apache-053'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable SSL Insecure Renegotiation'
    
    found_insecure_reneg = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        reneg_lines = content_lines.select { |line| line.match?(/^SSLInsecureRenegotiation/) }.join
        if reneg_lines.match?(/on/i)
          found_insecure_reneg = true
        end
      end
    end
    
    describe 'Apache: Disable SSL Insecure Renegotiation' do
      it 'should not include SSLInsecureRenegotiation on in any config file' do
        expect(found_insecure_reneg).to be false
      end
    end
  end

  # 54. Ensure SSL Compression is not Enabled
  control 'apache-no-ssl-compression' do
    impact 1.0
    title 'Ensure SSL Compression is not Enabled'
    desc 'The SSL Compression directive controls whether SSL compression is used by Apache when serving content over HTTPS. It is recommended that the SSL Compression directive be set to off.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'If SSL compression is enabled, HTTPS communication between the client and the server may beat increased risk to the CRIME attack. The CRIME attack increases a malicious actors ability to derive the value of a session cookie, which commonly contains an authenticator. If the authenticator in a session cookie is derived, it can be used to impersonate the account associated with the authenticator.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Search the Apache configuration files for the SSLCompression directive.
    2. If the directive is present, set it tff.
    Default Value:
    In Apache versions >= 2.4.3, the SSLCompression directive is available and SSL compression isimplicitly disabled. In Apache 2.4 - 2.4.2, the SSLCompression directive is not available andSSL compression is implicitly disabled.
    References:1. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html
    #sslcompression2. https://en.wikipedia.org/wiki/CRIME_(security_exploit)'
    tag vulnerability_id: 'Apache-054'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure SSL Compression is not Enabled'
    
    found_ssl_compression = false
    
    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content_lines = file(config_file).content.lines
                                          .map(&:strip)
                                          .reject { |line| line.empty? || line.start_with?('#') }
        
        compression_lines = content_lines.select { |line| line.match?(/^SSLCompression/) }.join
        if compression_lines.match?(/on/i)
          found_ssl_compression = true
        end
      end
    end
    
    describe 'Apache: Ensure SSL Compression is not Enabled' do
      it 'should not include SSLCompression on in any config file' do
        expect(found_ssl_compression).to be false
      end
    end
  end

  # 55. Disable the TLS v1.0 Protocol
  control 'apache-disable-tls10' do
    impact 1.0
    title 'Disable the TLS v1.0 Protocol'
    desc 'The TLSv1.0 protocol should be disabled via the SSLProtocol directive, if possible, as it hasbeen shown to be vulnerable to information disclosure.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The TLSv1.0 protocol is vulnerable to the BEAST attack when used in CBC mode (October2011). Unfortunately, the TLSv1.0 uses CBC modes for all of the block mode ciphers, which only leaves the RC4 streaming cipher. The RC4 cipher is not vulnerable to the BEAST attack; however, there is research that indicates it is also weak and is not recommended. Therefore, it is recommended that the TLSv1.0 protocol be disabled if all TLS clients support the newer TLS protocols. All major up-to-date browsers support TLSv1.1 and TLSv1.2; however, some older IE browsers (8,9,10) may still have TLSv1.1 and TLSv1.2 disabled for some strange reason. While Safari 6 does not support the newer TLS protocols. Review the Wikipedia reference for browser support details. Ensuring that all users browsers are configured to allow TLSv1.1 and TLSv1.2 is necessary before disabling TLSv1.0 on the Apache web server; therefore, this recommendation is a level 2 rather than a level 1. Disabling TLSv1.0 on internal only websites is more easily accomplished when access is limited to clients with browsers controlled by the organization policies and procedures to allow and prefer TLSv1.1 and higher. The NIST SP 800-52r1 guidelines for TLS configuration state that servers that supportgovernment-only applications shall not support TLSv1.0 or any of the SSL protocols. WhileServers that support citizen or business-facing applications may be configured to support TLSversion 1.0 in order to enable interaction with citizens and businesses. Also, it is important to note that Microsoft support for all older versions of IE ends January 12, 2016, and Apple ends support for Safari 6 with the fall release if OS X 10.11. So, it is wise to plan for usage of TLSv1.0 to be eliminated in 2016. Some organizations may find it helpful to implement a phasedtransitional plan where TLSv1.0 is not disabled, but the web server will detect browsers which do not have TLSv1.1 or newer enabled and redirect them to a web site that explains how toenabled the newer TLS protocols. The redirect can be implemented using the mod_rewritewhich can detect the protocol used and rewrite the URL to the helpful website.'
    tag remediation: 'Perform the following to implement the recommended state:
    Search the Apache configuration files for the SSLProtocol directive; add the directive, if notpresent, or change the value to TLSv1.1 TLSv1.2.
    Default Value:
    SSLProtocol all
    References:1. https://en.wikipedia.org/wiki/Transport_Layer_Security
    #Web_browsers- Browsersupport and defaults for SSL/TLS protocols2. https://community.qualys.com/blogs/securitylabs/2011/10/17/mitigating-the-beast-attackon-tls- Qualys - Ivan Ristic3. http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r1.pdf4. https://support.microsoft.com/en-us/gp/microsoft-internet-explorer'
    tag vulnerability_id: 'Apache-055'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable the TLS v1.0 Protocol'
    
    sslprotocol_found = false
    bad_sslprotocol_lines = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLProtocol\s+(.+)$/i
            sslprotocol_found = true
            value = $1
            # Accept both "TLSv1.2" and "-all +TLSv1.2" (and with TLSv1.3)
            unless value.strip.match?(/\A(TLSv1\.2(\s+TLSv1\.3)?|\-all\s+\+TLSv1\.2(\s+\+TLSv1\.3)?)\Z/i)
              bad_sslprotocol_lines << "#{config_file}:#{idx+1}:non-compliant SSLProtocol: #{l}"
            end
          end
        end
      end
    end

    describe 'Apache: Disable the TLS v1.0 Protocol' do
      it 'should have at least one SSLProtocol directive' do
        expect(sslprotocol_found).to be true
      end
      it 'should not allow TLSv1.0, SSLv2, SSLv3, or all in any SSLProtocol directive' do
        expect(bad_sslprotocol_lines).to be_empty, "Bad SSLProtocol: #{bad_sslprotocol_lines.join(', ')}"
      end
    end
  end

  # 56. Disable the TLS v1.1 Protocol
  control 'apache-disable-tls11' do
    impact 1.0
    title 'Disable the TLS v1.1 Protocol'
    desc 'The TLSv1.1 protocol should be disabled via the SSLProtocol directive, if possible, as it hasbeen shown to be vulnerable to information disclosure.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'The remote service accepts connections encrypted using TLS 1.1.
    TLS 1.1 lacks support for current and recommended cipher suites. Ciphers that support encryption before MAC computation, and authenticated encryption modes such as GCM cannot be used with TLS 1.1
    As of March 31, 2020, Endpoints that are not enabled for TLS 1.2 and higher will no longer function properly with major web browsers and major vendors.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Check if the TLSv1.3 protocol is supported by the Apache server by either checking
    that the version of OpenSSL is 1.1.1 or later or place the TLSv1.3 value in the
    SSLProtocol string of a configuration file and check the syntax with the "httpd -t"
    command before using the file in production. Two examples below are shown of
    servers that do support the TLSv1.3 protocol.
    $ openssl version
    OpenSSL 1.1.1a 20 Nov 2018
    ### _(Add TLSv1.3 to the SSLProtocol directive)_
    # httpd -t
    Syntax OK
    2. Search the Apache configuration files for the SSLProtocol directive; add the
    directive, if not present, or change the value to TLSv1.2 or TLSv1.2 TLSv1.3 if the
    TLSv1.3 protocol is supported.'
    tag vulnerability_id: 'Apache-056'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Disable the TLS v1.1 Protocol'
    
    sslprotocol_found = false
    bad_sslprotocol_lines = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLProtocol\s+(.+)$/i
            sslprotocol_found = true
            value = $1
            # Non-compliant if TLSv1.1, TLSv1.0, SSLv2, SSLv3, or all are present
            if value.match?(/\bTLSv1\.1\b/i) ||
               value.match?(/\bTLSv1(\s|$)/i) ||
               value.match?(/\bSSLv2\b/i) ||
               value.match?(/\bSSLv3\b/i) ||
               value.match?(/\ball\b/i)
              bad_sslprotocol_lines << "#{config_file}:#{idx+1}:#{l}"
            end
            # Accept both "TLSv1.2" and "-all +TLSv1.2" (and with TLSv1.3)
            unless value.strip.match?(/\A(TLSv1\.2(\s+TLSv1\.3)?|\-all\s+\+TLSv1\.2(\s+\+TLSv1\.3)?)\Z/i)
              bad_sslprotocol_lines << "#{config_file}:#{idx+1}:non-compliant SSLProtocol: #{l}"
            end
          end
        end
      end
    end

    describe 'Apache: Disable the TLS v1.1 Protocol' do
      it 'should have at least one SSLProtocol directive' do
        expect(sslprotocol_found).to be true
      end
      it 'should not allow TLSv1.1, TLSv1.0, SSLv2, SSLv3, or all in any SSLProtocol directive, and only allow TLSv1.2 or TLSv1.2 TLSv1.3' do
        expect(bad_sslprotocol_lines).to be_empty, "Bad SSLProtocol: #{bad_sslprotocol_lines.join(', ')}"
      end
    end
  end

  # 57. Enable TLS v1.2 and above
  control 'apache-enable-tls12' do
    impact 1.0
    title 'Enable TLS v1.2 and above'
    desc 'The remote service accepts connections encrypted using TLS 1.2'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'As of March 31, 2020, Endpoints that are not enabled for TLS 1.2 and higher will no longer function properly with major web browsers and major vendors.'
    tag remediation: 'Perform the following to implement the recommended state:
    1. Check if the TLSv1.3 protocol is supported by the Apache server by either checking
    that the version of OpenSSL is 1.1.1 or later or place the TLSv1.3 value in the
    SSLProtocol string of a configuration file and check the syntax with the "httpd -t"
    command before using the file in production. Two examples below are shown of
    servers that do support the TLSv1.3 protocol.
    $ openssl version
    OpenSSL 1.1.1a 20 Nov 2018
    ### _(Add TLSv1.3 to the SSLProtocol directive)_
    # httpd -t
    Syntax OK
    2. Search the Apache configuration files for the SSLProtocol directive; add the
    directive, if not present, or change the value to TLSv1.2 or TLSv1.2 TLSv1.3 if the
    TLSv1.3 protocol is supported.'
    tag vulnerability_id: 'Apache-057'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Enable TLS v1.2 and above'
    
    sslprotocol_found = false
    bad_sslprotocol_lines = []

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLProtocol\s+(.+)$/i
            sslprotocol_found = true
            value = $1
            # Accept both "TLSv1.2" and "-all +TLSv1.2" (and with TLSv1.3)
            unless value.strip.match?(/\A(TLSv1\.2(\s+TLSv1\.3)?|\-all\s+\+TLSv1\.2(\s+\+TLSv1\.3)?)\Z/i)
              bad_sslprotocol_lines << "#{config_file}:#{idx+1}:non-compliant SSLProtocol: #{l}"
            end
          end
        end
      end
    end

    describe 'Apache: Enable TLS v1.2 and above' do
      it 'should have at least one SSLProtocol directive' do
        expect(sslprotocol_found).to be true
      end
      it 'should set SSLProtocol to only TLSv1.2 or TLSv1.2 TLSv1.3 in all config files' do
        expect(bad_sslprotocol_lines).to be_empty, "Bad SSLProtocol: #{bad_sslprotocol_lines.join(', ')}"
      end
    end
  end

  # 58. Enable OCSP Stapling
  control 'apache-ocsp-stapling' do
    impact 1.0
    title 'Enable OCSP Stapling'
    desc 'The OCSP (Online Certificate Status Protocol) provides the current revocation status of an X.509certificate and allows for a certificate authority to revoke the validity of a signed certificatebefore its expiration date. The URI for the OCSP server is included in the certificate and verifiedby the browser. The Apache SSLUseStapling directive along with the SSLStaplingCachedirective are recommended to enable OCSP Stapling by the web server. If the client requestsOCSP stapling, then the web server can include the OCSP server response along with the webservers X.509 certificate.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'The OCSP protocol is a big improvement over CRLs (certificate revocation lists) for checking ifa certificate has been revoked. There are however some minor privacy and efficiency concerns with OCSP. The fact that the browser has to check a third-party CA discloses that the browser is configured for OCSP checking. Also, the already high overhead of making an SSL connection is increased by the need for the OCSP requests and responses. The OCSP stapling improves thesituation by having the SSL server "staple" an OCSP response, signed by the OCSP server, to thecertificate it presents to the client. This obviates the need for the client to ask the OCSP serverfor status information on the server certificate. However, the client will still need to make OCSPrequests on any intermediate CA certificates that are typically used to sign the servers certificate.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the SSLUseStapling directive to have a value of on in the Apache server level configuration and every virtual host that is SSL enabled. Also ensure that SSLStaplingCache is set to one of the three cache types similar to the examples below.
    SSLUseStapling On
    SSLStaplingCache ""shmcb:logs/ssl_staple_cache(512000)""
    - or-
    SSLStaplingCache ""dbm:logs/ssl_staple_cache.db""
    - or -
    SSLStaplingCache dc:UNIX:logs/ssl_staple_socket
    Default Value:
    SSLUseStapling Off SSLStaplingCache<no default value>
    References:
    1. https://en.wikipedia.org/wiki/OCSP_stapling - OCSP Stapling
    2. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html- Apache SSL Directives'
    tag vulnerability_id: 'Apache-058'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Enable OCSP Stapling'
    
    missing_stapling = []
    found_stapling_cache = false

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        content = file(config_file).content

        # Check for SSLStaplingCache
        content.lines.each do |line|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          found_stapling_cache ||= l.match?(/^SSLStaplingCache\s+(shmcb:|dbm:|dc:)/i)
        end

        # Check each <VirtualHost *:443> block for SSLUseStapling On
        content.scan(/<VirtualHost\s+[^>]*:443[^>]*>(.*?)<\/VirtualHost>/mi).each_with_index do |block, idx|
          vhost_body = block[0]
          has_stapling = vhost_body.lines.any? do |l|
            l.strip =~ /^SSLUseStapling\s+On/i
          end
          missing_stapling << "#{config_file} vhost ##{idx+1}" unless has_stapling
        end
      end
    end

    describe 'Apache: Enable OCSP Stapling' do
      it 'should have SSLUseStapling On in every SSL-enabled VirtualHost' do
        expect(missing_stapling).to be_empty, "Missing SSLUseStapling On in: #{missing_stapling.join(', ')}"
      end
      it 'should have SSLStaplingCache set globally' do
        expect(found_stapling_cache).to be true
      end
    end
  end

  # 59. Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled
  control 'apache-forward-secrecy' do
    impact 1.0
    title 'Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled'
    desc 'In cryptography, forward secrecy (FS), which is also known as perfect forward secrecy (PFS), is a feature of specific key exchange protocols that give assurance that your session keys will not be compromised even if the private key of the server is compromised. Protocols such as RSA do not provide the forward secrecy, while the protocols ECDHE (Elliptic-Curve Diffie-Hellman Ephemeral) and the DHE (Diffie-Hellman Ephemeral) will provide forward secrecy. The ECDHE is the stronger protocol and should be preferred, while the DHE may be allowed for greater compatibility with older clients. The TLS ciphers should be configured to require either the ECDHE or the DHE ephemeral key exchange, while not allowing other cipher suites.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'During the TLS handshake, after the initial client & server Hello, there is a pre-master
    secret generated, which is used to generate the master secret, and in turn generates the
    session key. When using protocols that do not provide forward secrecy, such as RSA, the
    pre-master secret is encrypted by the client with the servers public key and sent over the
    network. However, with protocols such as ECDHE (Elliptic-Curve Diffie-Hellman Ephemeral)
    the pre-master secret is not sent over the wire, even in encrypted format. The key exchange
    arrives at the shared secret in the clear using ephemeral keys that are not stored or used
    again. With FS, each session has a unique key exchange, so that future sessions are
    protected.'
    tag remediation: 'Perform one of the following to implement the recommended state:
    • Add or modify the following line in the Apache server level configuration and every
    virtual host that is SSL/TLS enabled:
    SSLCipherSuite EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA
    • The more recent versions of openssl (such as 1.0.2 and newer) will support the
    usage of ECDHE as a synonym for EECDH and DHE as a synonym for EDH in the cipher
    specification. The usage of ECDHE and DHE are preferred so that the specification
    matches the expected output. So, the cipher specification could be:
    SSLCipherSuite ECDHE:DHE:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA'
    tag vulnerability_id: 'Apache-059'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled'
    
    bad_sslciphersuite_lines = []
    found_sslciphersuite = false

    # Accept both ECDHE/DHE (preferred) and EECDH/EDH (legacy) as compliant
    forward_secrecy_patterns = [
      /\A\s*SSLCipherSuite\s+(ECDHE|EECDH):?(DHE|EDH)?:.*!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA/i,
      /\A\s*SSLCipherSuite\s+(DHE|EDH):?(ECDHE|EECDH)?:.*!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA/i
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLCipherSuite\s+(.+)$/i
            found_sslciphersuite = true
            unless forward_secrecy_patterns.any? { |pat| l.match?(pat) }
              bad_sslciphersuite_lines << "#{config_file}:#{idx+1}:#{l}"
            end
          end
        end
      end
    end

    describe 'Apache: Ensure Only Cipher Suites That Provide Forward Secrecy Are Enabled' do
      it 'should have at least one SSLCipherSuite directive' do
        expect(found_sslciphersuite).to be true
      end
      it 'should only include forward secrecy ciphers and required exclusions in all SSLCipherSuite directives' do
        expect(bad_sslciphersuite_lines).to be_empty, "Non-compliant SSLCipherSuite: #{bad_sslciphersuite_lines.join(', ')}"
      end
    end
  end

  # 60. Set Timeout Limits for the Request Body
  control 'apache-timeout-body' do
    impact 1.0
    title 'Set Timeout Limits for the Request Body'
    desc 'The RequestReadTimeout directive also allows setting timeout values for the body portion of a request.
    The directive provides for an initial timeout value, and a maximum timeout and minimum rate. The
    minimum rate specifies that after the initial timeout, the server will wait an additional 1 second
    for each N bytes are received. The recommended setting is to have a maximum timeout of 20 seconds
    or less. The default value is body=20,MinRate=500.'

    # Custom tags for report generation
    tag risk_rating: 'Low'
    tag severity: 'Low'
    tag impact_description: 'It is not sufficient to timeout only on the header portion of the request, as the server will still bevulnerable to attacks like the OWASP Slow POST attack, which provide the body of the requestvery slowly. Therefore, the body portion of the request must have a timeout as well. A timeout of20 seconds or less is recommended.'
    tag remediation: '1. Load the mod_requesttimeout module in the Apache configuration:
    LoadModule reqtimeout_module modules/mod_reqtimeout.so
    2. Add a RequestReadTimeout directive with the maximum request body timeout value of 20 seconds or less, for example:
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
    Default Value:
    body=20,MinRate=500
    Reference: https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html'
    tag vulnerability_id: 'Apache-060'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Set Timeout Limits for the Request Body'

    found_reqtimeout_module = false
    found_body_limit = false

    CONFIG_FILES.each do |config_file|
      next unless file(config_file).exist?
      content = file(config_file).content

      # Check for LoadModule for mod_reqtimeout
      found_reqtimeout_module ||= !!content.match(/^\s*LoadModule\s+reqtimeout_module/)

      # Find RequestReadTimeout body=... with max 20 or less
      content.scan(/^\s*RequestReadTimeout\s+([^\n]+)/).each do |line|
        params = line[0]
        if params.match(/body=(\d+)-(\d+)/)
          min, max = params.match(/body=(\d+)-(\d+)/).captures.map(&:to_i)
          found_body_limit ||= (max <= 20)
        elsif params.match(/body=(\d+)/)
          single = params.match(/body=(\d+)/)[1].to_i
          found_body_limit ||= (single <= 20)
        end
      end
    end

    describe 'Apache: Set Timeout Limits for the Request Body' do
      it 'should have mod_reqtimeout loaded' do
        expect(found_reqtimeout_module).to be true
      end

      it 'should have RequestReadTimeout body timeout max 20 or less' do
        expect(found_body_limit).to be true
      end
    end
  end

  # 61. Restrict Medium Strength SSL/TLS Ciphers
  control 'apache-restrict-medium-ciphers' do
    impact 1.0
    title 'Restrict Medium Strength SSL/TLS Ciphers'
    desc 'The SSLCipherSuite directive specifies which ciphers are allowed in the negotiation with the client.
    Disable the medium strength ciphers such as Triple DES (3DES) and IDEA by adding !3DES and !IDEA
    in the SSLCipherSuite directive.'

    # Custom tags for report generation
    tag risk_rating: 'Medium'
    tag severity: 'Medium'
    tag impact_description: 'Although Triple DES has been a trusted standard in the past, several vulnerabilities for it have been published over the years and it is no longer considered secure. A somewhat recent vulnerable against 3DES in CBC mode was nicknamed the SWEET32 attack, was published in2016 as CVE-2016-2183. The IDEA cipher in CBC mode, is also vulnerable to the SWEET32 attack.'
    tag remediation: 'Perform the following to implement the recommended state:
    Add or modify the following line in the Apache server level configuration and every virtual host that is SSL/TLS enabled:
    SSLCipherSuite ALL:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL:!3DES:!IDEA
    Default Value:
    The following are the default values: SSLCipherSuite default depends on OpenSSL version.
    References:
    1. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol
    2. https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslciphersuite
    3. https://sweet32.info/
    4. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183
    5. https://github.com/rbsec/sslscan
    6. https://www.openssl.org/'
    tag vulnerability_id: 'Apache-061'
    tag compliance_framework: ['Apache HTTP Server Security Benchmark']
    tag check_name: 'Restrict Medium Strength SSL/TLS Ciphers'

    bad_sslciphersuite_lines = []
    found_sslciphersuite = false

    forward_secrecy_patterns = [
      /\A\s*SSLCipherSuite\s+(ECDHE|EECDH):?(DHE|EDH)?:.*!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA/i,
      /\A\s*SSLCipherSuite\s+(DHE|EDH):?(ECDHE|EECDH)?:.*!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA/i
    ]

    CONFIG_FILES.each do |config_file|
      if file(config_file).exist?
        file(config_file).content.lines.each_with_index do |line, idx|
          l = line.strip
          next if l.empty? || l.start_with?('#')
          if l =~ /^SSLCipherSuite\s+(.+)$/i
            found_sslciphersuite = true
            unless forward_secrecy_patterns.any? { |pat| l.match?(pat) }
              bad_sslciphersuite_lines << "#{config_file}:#{idx+1}:#{l}"
            end
          end
        end
      end
    end

    describe 'Apache: SSLCipherSuite presence and composition' do
      it 'should have at least one SSLCipherSuite directive to inspect' do
        expect(found_sslciphersuite).to be true
      end

      it 'should prefer forward secrecy and include required exclusions (!3DES and !IDEA among others)' do
        expect(bad_sslciphersuite_lines).to be_empty, "Non-compliant SSLCipherSuite lines: #{bad_sslciphersuite_lines.join('; ')}"
      end
    end
  end
end
