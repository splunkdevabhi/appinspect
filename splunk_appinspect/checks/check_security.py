# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Security vulnerabilities
"""

# Python Standard Libraries
import logging
import os
import re
# Custom Libraries
import splunk_appinspect
import platform


logger = logging.getLogger(__name__)
report_display_order = 5

potentially_dangerous_windows_filetypes = ['.cmd', '.ps1', '.bat', '.ps2',
                                           '.ws', '.wsf', '.psc1', '.psc2']


@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_pexpect(app, reporter):
    """Check for use of `pexpect` to ensure it is only controlling app 
    processes.
    """
    for match in app.search_for_pattern('pexpect.run', types=['.py']):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Possible use of pexpect- detected in {}. "
                           "File: {}, Line: {}."
                           ).format(match[0], filename, line)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_secret_disclosure(app, reporter):
    """Check for passwords and secrets."""
    secret_patterns = (r"((?i)(login|passwd|password|community|privpass)\s*=\s*[^\s]+|"                # General secret 
                       r"https?://[^/]+/[^\"\'\s]*?(key|pass|pwd|token)[0-9a-z]*\=[^&\"\'\s]+|"        # Secrets in the url
                       r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})|"                      # Slack Token
                       r"-----BEGIN RSA PRIVATE KEY-----|"                                             # RSA private key
                       r"-----BEGIN OPENSSH PRIVATE KEY-----|"                                         # SSH (OPENSSH) private key
                       r"-----BEGIN DSA PRIVATE KEY-----|"                                             # SSH (DSA) private key
                       r"-----BEGIN EC PRIVATE KEY-----|"                                              # SSH (EC) private key
                       r"-----BEGIN PGP PRIVATE KEY BLOCK-----|"                                       # PGP private key block
                       r"f(ace)?b(ook)?.{0,10}=\s*[\'\"]EAA[0-9a-z]{180,}[\'\"]|"                      # Facebook user token
                       r"f(ace)?b(ook)?.{0,10}=\s*[\'\"]\d+\|[0-9a-z]+[\'\"]|"                         # Facebook app token
                       r"github.{0,10}=\s*[\'\"][0-9a-f]{40}[\'\"]|"                                   # GitHub personal access token
                       r"(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")|"                                   # Google Oauth
                       r"AKIA[0-9A-Z]{16}|"                                                            # AWS API Key
                       r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})")       # Heroku API Key

    for match in app.search_for_pattern(secret_patterns):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Possible secret disclosure in {}: {}."
                           " File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.1')
def check_for_sensitive_info_in_url(app,reporter):
    """Check for sensitive information being exposed in transit via URL query string parameters"""
    sensitive_info_patterns = (r"((?i).*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=.{0,100}(key|password|pass|pwd|token|cridential|secret|login|auth).*|"                     # Single line url
                               r".*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=.{0,100}\.format\([^\)]*(key|password|pass|pwd|token|cridential|secret|login|auth)[^\)]*\)+?)")  # Multi line url
    sensitive_info_patterns_for_report = (r"((?i)(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=.{0,100}(key|password|pass|pwd|token|cridential|secret|login|auth)|"                     # Single line url
                                          r"(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=.{0,100}\.format\([^\)]*(key|password|pass|pwd|token|cridential|secret|login|auth)[^\)]*\)+?)")  # Multi line url
        
    for match in app.search_for_crossline_pattern(pattern=sensitive_info_patterns, cross_line=5):
        filename, line = match[0].rsplit(":", 1)
        ''' handle massage '''
        for rx in [re.compile(p) for p in [sensitive_info_patterns_for_report]]:
            for p_match in rx.finditer(match[1].group()):
                description = p_match.group()
        reporter_output = ("Possible sensitive information being exposed via URL in {}: {}."
                           " File: {}, Line: {}."
                           ).format(match[0],
                                    #match[1].group(),
                                    description,
                                    filename,
                                    line)

        reporter.manual_check(reporter_output, filename, line)



@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_vbs_command_injection(app, reporter):
    """Check for command injection in VBS files."""
    for match in app.search_for_pattern('Shell.*Exec', types=['.vbs']):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Possible command injection in {}: {}."
                           " File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.manual_check(reporter_output, filename, line)



@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_command_injection_through_env_vars(app, reporter):
    """Check for command injection through environment variables."""
    for match in app.search_for_pattern('start.*%', types=potentially_dangerous_windows_filetypes):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Possible command injection in {}: {}."
                           " File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_insecure_http_calls_in_python(app, reporter):
    """Check for insecure HTTP calls in Python."""
    insecure_http_patterns = ["HTTPConnection", "socket", "urllib*"]
    matches = app.search_for_patterns(insecure_http_patterns, types=[".py"])
    for (fileref_output, match) in matches:
        filepath, line_number = fileref_output.rsplit(":", 1)
        reporter_output = ("Possible insecure HTTP Connection."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(match.group(),
                                    filepath,
                                    line_number)
        reporter.manual_check(reporter_output, filepath, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_stacktrace_returned_to_user(app, reporter):
    """Check that stack traces are not being returned to an end user."""
    for match in app.search_for_pattern('format_exc', types=['.py']):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Stacktrace being formatted in {}: {}."
                           "File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_environment_variable_use_in_python(app, reporter):
    """Check for environment variable manipulation and attempts to monitor
    sensitive environment variables."""
    # Catch `os.environ.get(` or `os.getenv(` but allow for `"SPLUNK_HOME` or
    # `'SPLUNK_HOME`
    # Catch `os.environ` other than `os.environ.get` (which is covered above)
    env_manual_regex = (r"((os[\s]*\.[\s]*environ[\s]*\.[\s]*get)"
                        r"|(os[\s]*\.[\s]*getenv))"
                        r"(?![\s]*\([\s]*[\'\"]SPLUNK\_HOME)"
                        r"|(os[\s]*\.[\s]*environ(?![\s]*\.[\s]*get))")
    for match in app.search_for_pattern(env_manual_regex, types=['.py']):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Environment variable being used in {}: {}."
                           "File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.manual_check(reporter_output, filename, line)
    # Fail for use of `os.putenv` / `os.unsetenv` in any scenario
    env_set_regex = r"(os[\s]*\.[\s]*putenv|os[\s]*\.[\s]*unsetenv)"
    for match in app.search_for_pattern(env_set_regex, types=['.py']):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = ("Environment variable manipulation detected in {}: {}."
                           "File: {}, Line: {}."
                           ).format(match[0],
                                    match[1].group(),
                                    filename,
                                    line)
        reporter.fail(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.5.2')
def check_symlink_outside_app(app, reporter): 
    """ Check no symlink points to the file outside this app """
    if platform.system() == "Windows":
        reporter_output = 'Symlink checks will be done manually during code review.'
        reporter.manual_check(reporter_output)
    else:
        for basedir, file, ext in app.iterate_files():
            app_file_path = os.path.join(basedir, file)
            full_file_path = app.get_filename(app_file_path)
            # it is a symbolic link file
            if os.path.islink(full_file_path):
                # For python 2.x, os.path.islink will always return False in windows
                # both of them are absolute paths
                link_to_absolute_path = os.path.abspath(os.path.realpath(full_file_path))
                app_root_dir = app.app_dir
                # link to outer path
                if not link_to_absolute_path.startswith(app_root_dir):
                    reporter_output = ('Link file found in path: {}. The file links to a '
                                'path outside of this app, the link path is: {}. File: {}'
                                ).format(full_file_path,
                                        link_to_absolute_path,
                                        app_file_path)
                    reporter.fail(reporter_output, app_file_path)
