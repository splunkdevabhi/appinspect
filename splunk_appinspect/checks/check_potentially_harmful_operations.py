# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Operating system standards
"""

# Python Standard Libraries
import logging
import os
import platform
# Custom Libraries
import splunk_appinspect

report_display_order = 5
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
def check_hard_coded_paths(app, reporter):
    """Check for hard-coded filepaths in scripts relative to author's local
    developer environment, or absolute paths.
    """
    # Dashboards and javascript files use a lot of URLs and fragments. JAR
    # files use them too.
    # added Windows drive letter, UNC paths (ACD-634), details are as follows:
    # (?:(?:[a-zA-Z]:|\\\\[a-zA-Z0-9_.$\ -]+\\[a-zA-Z0-9_.$\ -]+)\\|  # Drive
    # (?:[^\\/:*?"<>|\r\n]+\\)*  (Folder)
    # [^\\/:*?"<>|\r\n]*  (File)
    pattern_to_search_for = r'([a-zA-Z]:|\\\\[a-zA-Z0-9_.$ -]+\\[a-zA-Z0-9_.$ -]+)\\((?:[^\\/:*?"<>|\r\n]+\\)*)([^\\/:*?"<>|\r\n]*)$' \
                            r'|(?:^|\b|\s)(/[^/ ]*)+/?$'
    excluded_directories = ["samples", "lookups", "static", "README"]
    excluded_types = [".ai",
                      ".conf", ".css", ".csv",
                      ".dat", ".dic",
                      ".gif",
                      ".htm", ".html",
                      ".jar", ".jpeg", ".jpg", ".js",
                      ".kmz",
                      ".md",
                      ".pdf", ".png",
                      ".rtf",
                      ".svg",
                      ".txt",
                      ".xml"]

    results = app.search_for_pattern(pattern_to_search_for,
                                     excluded_dirs=excluded_directories,
                                     excluded_types=excluded_types)
    for result, match in results:
        file_name, line_number = result.rsplit(":", 1)
        if platform.system() == "Windows":
            reporter_output = ("{} will be checked for hard-coded paths during code review.").format(result)
            reporter.manual_check(reporter_output, file_name, line_number)
        else:
            # Only search text files, not binaries
            if app.is_text(file_name):
                reporter_output = ("Found possible hard-coded path '{}'"
                                   " File: {}"
                                   " Line: {}").format(match.group(),
                                                       result,
                                                       line_number)
                reporter.manual_check(reporter_output, file_name, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
def check_user_privileges(app, reporter):
    """Check that scripts are not trying to switch into other user accounts,
    create new users, run sudo.
    """
    patterns = ['sudo[\'"\s]', 'adduser', 'useradd', 'su[\'"\s]\s*\w+']
    excluded_directories = ["lookups"]
    excluded_types = [".gif", ".gz", ".jpg", ".md", ".png", ".tar", ".tgz",
                      ".txt", ".woff"]

    # Excluding binary types- su in particular is a pretty low bar to hit.
    matches = app.search_for_patterns(patterns, excluded_dirs=excluded_directories,
                                                excluded_types=excluded_types)
    for (fileref_output, match) in matches:
        filepath, line_number = fileref_output.split(":")
        reporter_output = ("The prohibited command {} was found."
                           " File: {}"
                           " Line: {}.").format(match.group(),
                                                filepath,
                                                line_number)
        reporter.manual_check(reporter_output, filepath, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval', 'cloud', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
def check_destructive_commands(app, reporter):
    """Check for the use of malicious commands designed to corrupt the OS or
    Splunk instance.
    """
    # The second is to match process.call(["rm", "-rf"]) and friends
    exclude = [".txt", ".md", ".org"]
    patterns = ["rm -rf", "[\"\']rm[\"\']\s*,\s*[\"\']\-[rf]{2}[\"\']",
                "kill\b", "halt\b"]
    matches = app.search_for_patterns(patterns, excluded_types=exclude)
    for (fileref_output, match) in matches:
        filepath, line_number = fileref_output.split(":")
        reporter_output = ("The prohibited command {} was found."
                           " File: {}"
                           " Line: {}.").format(match.group(),
                                                filepath,
                                                line_number)
        reporter.manual_check(reporter_output, filepath, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.0.0')
def check_fs_writes(app, reporter):
    """Check that applications only write to the following directories
    `<SPLUNK_HOME>/etc/<APP_NAME>/local`,
    `<SPLUNK_HOME>/etc/<APP_NAME>/lookup`
    `<SPLUNK_HOME>/var/log/<APP_NAME>/<LOG_NAME>.log`,
    `<SPLUNK_HOME>/var/log/<APP_NAME>.log`
    `<SPLUNK_HOME>/var/run` and OS temporary directories.
    """
    reporter.manual_check(
        "File access will be inspected during code review.")
