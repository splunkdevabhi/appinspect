# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Source code and binaries standards
"""

# TODO: Provide url link to the criteria here in the docstring
# Python Standard library
import json
import logging
import mimetypes
import os
import re
import subprocess
import stat
import sys
import platform
# Third-Party Modules
# Custom Modules
import splunk_appinspect


logger = logging.getLogger(__name__)
report_display_order = 5


@splunk_appinspect.tags("splunk_appinspect", "appapproval")
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_bin_files(app, reporter):
    """Check that files outside of the `bin/` directory do not have execute
    permissions and are not .exe files. Splunk recommends 644 for all app files
    outside of the `bin/` directory, 644 for scripts within the `bin/` directory
    that are invoked using an interpreter (e.g. `python my_script.py` or
    `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are
    invoked directly (e.g. `./my_script.sh` or `./my_script`).
    """
    directories_to_exclude = ["bin"]
    for dir, file, ext in app.iterate_files(excluded_dirs=directories_to_exclude):
        current_file_relative_path = os.path.join(dir, file)
        current_file_full_path = app.get_filename(current_file_relative_path)
        file_statistics = os.stat(current_file_full_path)
        # Checks the file's permissions against execute flags to see if the file
        # is executable
        if bool(file_statistics.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            reporter.fail(
                "This file has execute permissions for owners, groups, or others: {}".format(current_file_relative_path))
        elif ext == ".exe":
            reporter_output = ("An executable file was detected:"
                               " File: {}").format(current_file_full_path)
            reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "manual")
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_executable_flag(app, reporter):
    """Check that files outside of the `bin/` directory do not appear to be
    executable according to the Unix `file` command. From `man file`: files have
    a ``magic number'' stored in a particular place near the beginning of the
    file that tells the UNIX operating system that the file is a binary
    executable."""
    if platform.system() == "Windows":
        # TODO: tests needed
        reporter_output = "Windows file permissions will be inspected during review."
        reporter.manual_check(reporter_output)
    else:
        directories_to_exclude = ["bin"]
        for directory, file, ext in app.iterate_files(excluded_dirs=directories_to_exclude):
            current_file_relative_path = os.path.join(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)
            file_output = subprocess.check_output(["file", current_file_full_path])
            file_output_regex = re.compile("(.)*executable(.)*",
                                           re.DOTALL | re.IGNORECASE | re.MULTILINE)
            if re.match(file_output_regex, file_output):
                reporter_output = ("The executable will be inspected during code review: "
                                   " File: {}").format(current_file_relative_path)
                reporter.manual_check(reporter_output, current_file_relative_path)


@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_urls_in_files(app, reporter):
    """Check that URLs do not include redirect or requests from external web
    sites.
    """
    # It's a little verbose but with the explicit-ness comes
    # References
    # http://tools.ietf.org/html/rfc3986
    # http://stackoverflow.com/questions/4669692/valid-characters-for-directory-part-of-a-url-for-short-links
    url_regex_pattern = ("(\w*://)+"                  # Captures protocol
                         "([\w\d\-]+\.[\w\d\-\.]+)+"  # Captures hostname
                         "(:\d*)?"                    # Captures port
                         "(\/[^\s\?]*)?"              # Captures path
                         "(\?[^\s]*)?")               # Capture query string
    url_regex_object = re.compile(url_regex_pattern,
                                  re.IGNORECASE)

    excluded_types = [".csv", ".gif", ".jpeg", ".jpg", ".md", ".org", ".pdf",
                      ".png", ".svg", ".txt"]
    excluded_directories = ["samples"]

    url_matches = app.search_for_pattern(url_regex_pattern,
                                         excluded_dirs=excluded_directories,
                                         excluded_types=excluded_types)

    if url_matches:
        for (fileref_output, match) in url_matches:
            url_match = match.group()
            filename, line_number = fileref_output.rsplit(":", 1)

            reporter_output = ("A file was detected contains that a url."
                               " Match: {}"
                               " File: {}"
                               " Line: {}"
                               ).format(url_match,
                                        filename,
                                        line_number)
            reporter.manual_check(reporter_output, filename, line_number)


@splunk_appinspect.tags('splunk_appinspect', 'cloud')
@splunk_appinspect.cert_version(min='1.0.0')
def check_requires_adobe_flash(app, reporter):
    """Check that the app does not use Adobe Flash files."""
    flash_file_types = [".f4v", ".fla", ".flv", ".jsfl", ".swc", ".swf", ".swt",
                        ".swz", ".xfl"]
    flash_files = [os.path.join(f[0], f[1])
                   for f
                   in app.iterate_files(types=flash_file_types)]
    if len(flash_files) > 0:
        for flash_file in flash_files:
            reporter_output = ("Flash file was detected. File: {}"
                               ).format(flash_file)
            reporter.fail(reporter_output)
    else:
        reporter_output = "Didn't find any flash files"
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect')
@splunk_appinspect.cert_version(min='1.0.0')
def check_for_expansive_permissions(app, reporter):
    """Check that no files have *nix write permissions for all users
    (xx2, xx6, xx7). Splunk recommends 644 for all app files outside of the
    `bin/` directory, 644 for scripts within the `bin/` directory that are
    invoked using an interpreter (e.g. `python my_script.py` or
    `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are
    invoked directly (e.g. `./my_script.sh` or `./my_script`).
    """
    offending_files = []
    for dir, file, ext in app.iterate_files():
        try:
            st = os.stat(app.get_filename(dir, file))
            if bool(st.st_mode & stat.S_IWOTH):
                offending_files.append(os.path.join(dir, file))
        except:
            pass

    for offending_file in offending_files:
        reporter_output = ("A world-writable file was found."
                           " File: {}"
                           ).format(offending_file)
        reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_hidden_files(app, reporter):
    """Check that there are no hidden files or directories."""
    offending_files = []
    for base, dirs, files in os.walk(app.app_dir):
        for elem in dirs + files:
            if elem.startswith("."):
                path = os.path.join(base, elem).replace(app.app_dir, "")
                offending_files.append(path)
    reporter_output = ("The following hidden files were found: {}"
                       ).format(", ".join(offending_files))
    reporter.assert_fail(len(offending_files) == 0, reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "manual")
@splunk_appinspect.cert_version(min="1.0.0")
def check_platform_specific_binaries(app, reporter):
    """Check that documentation declares platform-specific binaries."""
    # Can't read the documentation, but we can check for native binaries
    # TODO: we should not be generating manual checks if directories are empty
    bin_directories = [bin_directory
                       for arch in app.arch_bin_dirs
                       if arch != app.DEFAULT_ARCH
                       for bin_directory in app.arch_bin_dirs[arch]]
    if app.some_directories_exist(bin_directories):
        reporter_output = ("Documentation will be read during code review.")
        reporter.manual_check(reporter_output)
    else:
        reporter_output = ("No platform-specific binaries found.")
        reporter.not_applicable(reporter_output)
