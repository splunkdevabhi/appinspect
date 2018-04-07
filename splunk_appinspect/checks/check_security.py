# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Security vulnerabilities
"""

# Python Standard Libraries
import logging
import os
# Custom Libraries
import splunk_appinspect


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
        reporter_output = ("Possible use of pexpect- detected in {}."
                           ).format(match[0])
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_secret_disclosure(app, reporter):
    """Check for passwords and secrets."""
    for match in app.search_for_pattern('(login|passwd|password|community|privpass)\s*=\s*[^\s]+'):
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(
            "Possible secret disclosure in {}: {}".format(match[0], match[1].group()), filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_vbs_command_injection(app, reporter):
    """Check for command injection in VBS files."""
    for match in app.search_for_pattern('Shell.*Exec', types=['.vbs']):
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(
            "Possible command injection in {}: {}".format(match[0], match[1].group()), filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_command_injection_through_env_vars(app, reporter):
    """Check for command injection through environment variables."""
    for match in app.search_for_pattern('start.*%', types=potentially_dangerous_windows_filetypes):
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(
            "Possible command injection in {}: {}".format(match[0], match[1].group()), filename, line)


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
                           " Line Number: {}"
                           ).format(match.group(), filepath, line_number)
        reporter.manual_check(reporter_output, filepath, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_stacktrace_returned_to_user(app, reporter):
    """Check that stack traces are not being returned to an end user."""
    for match in app.search_for_pattern('format_exc', types=['.py']):
        reporter_output = ("Stacktrace being formatted in {}: {}"
                           ).format(match[0], match[1].group())
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud')
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
        reporter_output = ("Environment variable being used in {}: {}"
                           ).format(match[0], match[1].group())
        filename, line = match[0].rsplit(":", 1)
        reporter.manual_check(reporter_output, filename, line)
    # Fail for use of `os.putenv` / `os.unsetenv` in any scenario
    env_set_regex = r"(os[\s]*\.[\s]*putenv|os[\s]*\.[\s]*unsetenv)"
    for match in app.search_for_pattern(env_set_regex, types=['.py']):
        reporter_output = ("Environment variable manipulation detected in {}: {}"
                           ).format(match[0], match[1].group())
        filename, line = match[0].rsplit(":", 1)
        reporter.fail(reporter_output, filename, line)


@splunk_appinspect.tags('splunk_appinspect', 'security', 'cloud')
@splunk_appinspect.cert_version(min='1.5.2')
def check_symlink_outside_app(app, reporter):
    """ Check no symlink points to the file outside this app """
    for basedir, file, ext in app.iterate_files():
        app_file_path = os.path.join(basedir, file)
        full_file_path = app.get_filename(app_file_path)
        # it is a symbolic link file
        if os.path.islink(full_file_path):
            # both of them are absolute paths
            link_to_absolute_path = os.path.abspath(os.path.realpath(full_file_path))
            app_root_dir = app.app_dir
            # link to outer path
            if not link_to_absolute_path.startswith(app_root_dir):
                reporter.fail('link file found in path: {}. It links to a path outside this app,' +
                              'the link path is: {}'.format(full_file_path, link_to_absolute_path))