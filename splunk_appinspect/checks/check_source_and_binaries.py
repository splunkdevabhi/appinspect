# Copyright 2018 Splunk Inc. All rights reserved.

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
from UserString import MutableString

# Third-Party Modules
if not platform.system() == "Windows":
    import magic
else:
    import win32security
    import ntsecuritycon as con
# Custom Modules
import splunk_appinspect

logger = logging.getLogger(__name__)
report_display_order = 5


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "cloud")
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_bin_files(app, reporter):
    """Check that files outside of the `bin/` and `appserver/controllers` directory do not have execute
    permissions and are not .exe files. Splunk recommends 644 for all app files
    outside of the `bin/` directory, 644 for scripts within the `bin/` directory
    that are invoked using an interpreter (e.g. `python my_script.py` or
    `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are
    invoked directly (e.g. `./my_script.sh` or `./my_script`).
    """
    directories_to_exclude_from_root = ["bin"]
    if platform.system() == "Windows":
        EXCLUDED_USERS_LIST = ['Administrators', 'SYSTEM', 'Authenticated Users']
        ACCESS_ALLOWED_ACE = 0
        for dir, filename, ext in app.iterate_files(excluded_dirs=directories_to_exclude_from_root):
            if dir == "appserver\\controllers\\":
                continue
            current_file_relative_path = os.path.join(dir, filename)
            current_file_full_path = app.get_filename(current_file_relative_path)
            if ext == ".exe":
                reporter_output = ("An executable file was detected. File: {}").format(current_file_relative_path)
                reporter.fail(reporter_output, current_file_relative_path)
            else:
                sd = win32security.GetFileSecurity(current_file_full_path, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl is None:
                    dacl = _new_dacl_with_all_control()
                ace_count = dacl.GetAceCount()
                for i in range(ace_count):
                    rev, access, usersid = dacl.GetAce(i)
                    user, group, type = win32security.LookupAccountSid('', usersid)
                    ace_type = rev[0]
                    if ace_type == ACCESS_ALLOWED_ACE and user not in EXCLUDED_USERS_LIST \
                            and _has_permission(access, con.FILE_GENERIC_EXECUTE):
                            reporter.warn(
                                "This file has execute permissions for users otherwise Administrators, SYSTEM and Authenticated Users",
                                current_file_relative_path)
    else:
        for dir, filename, ext in app.iterate_files(excluded_dirs=directories_to_exclude_from_root):
            # filter appserver/controllers/ out
            if dir == "appserver/controllers/":
                continue
            current_file_relative_path = os.path.join(dir, filename)
            current_file_full_path = app.get_filename(current_file_relative_path)
            file_statistics = os.stat(current_file_full_path)
            # Checks the file's permissions against execute flags to see if the file
            # is executable
            if bool(file_statistics.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                reporter.fail(
                    "This file has execute permissions for owners, groups, or others. File: {}"
                        .format(current_file_relative_path), current_file_relative_path)
            elif ext == ".exe":
                reporter_output = ("An executable file was detected. File: {}").format(current_file_relative_path)
                reporter.fail(reporter_output, current_file_relative_path)


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "manual", "cloud")
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
            # filter appserver/controllers/ out
            if directory == "appserver/controllers/":
                continue
            current_file_relative_path = os.path.join(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)
            if current_file_relative_path in app.info_from_file:
                file_output = app.info_from_file[current_file_relative_path]
            else:
                file_output = magic.from_file(current_file_full_path)
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
        # {url_pattern: {filename: [lineno_list]}}
        result_dict = {}

        for (fileref_output, match) in url_matches:
            url_match = match.group()
            filename, line_number = fileref_output.rsplit(":", 1)

            if url_match not in result_dict:
                result_dict[url_match] = {}
            if filename not in result_dict[url_match]:
                result_dict[url_match][filename] = []
            result_dict[url_match][filename].append(str(line_number))

            reporter_output = ("A file was detected that contains that a url."
                               " Match: {}"
                               " File: {}"
                               " Line: {}"
                               ).format(url_match,
                                        filename,
                                        line_number)
            reporter.manual_check(reporter_output, filename, line_number)

        # create some extra manual checks in order to see results in a more convenient way
        for (url_match, file_dict) in result_dict.items():
            reporter_output = MutableString()
            reporter_output.append("A url {} was detected in the following files".format(url_match))
            for (file_name, lineno_list) in file_dict.items():
                reporter_output.append(", (File: {}, Linenolist: [{}])".format(file_name, ', '.join(lineno_list)))
            # don't need filename and line_number here, since it is an aggregated result
            reporter.manual_check(str(reporter_output))


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
            reporter.fail(reporter_output, flash_file)
    else:
        reporter_output = "Didn't find any flash files."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'windows')
@splunk_appinspect.cert_version(min='1.0.0')
def check_for_expansive_permissions(app, reporter):
    """Check that no files have *nix write permissions for all users
    (xx2, xx6, xx7). Splunk recommends 644 for all app files outside of the
    `bin/` directory, 644 for scripts within the `bin/` directory that are
    invoked using an interpreter (e.g. `python my_script.py` or
    `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are
    invoked directly (e.g. `./my_script.sh` or `./my_script`).
    Since appinspect 1.6.1, check that no files have nt write permissions for all users.
    """
    offending_files = []
    EXCLUDED_USERS_LIST = ['Administrators', 'SYSTEM', 'Authenticated Users']
    ACCESS_ALLOWED_ACE = 0
    for dir, file, ext in app.iterate_files():
        try:
            if os.name != "nt":
                st = os.stat(app.get_filename(dir, file))
                if bool(st.st_mode & stat.S_IWOTH):
                    offending_files.append(os.path.join(dir, file))
            else:
                # full path in GetFileSecurity should be 
                # the absolute path in Windows
                full_path = os.path.join(app.app_dir, dir, file)
                sd = win32security.GetFileSecurity(full_path, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl is None:
                    dacl = _new_dacl_with_all_control()
                # get the number of access control entries
                ace_count = dacl.GetAceCount()
                for i in range(ace_count):
                    # rev: a tuple of (AceType, AceFlags)
                    # access: ACCESS_MASK
                    # usersid: SID
                    rev, access, usersid = dacl.GetAce(i)
                    user, group, type = win32security.LookupAccountSid('', usersid)
                    ace_type = rev[0]
                    # only need to consider AceType = ACCESS_ALLOWED_ACE
                    # not check users named "SYSTEM", "Administrators" and "Authenticated Users"
                    if ace_type == ACCESS_ALLOWED_ACE and user not in EXCLUDED_USERS_LIST \
                            and _has_permission(access, con.FILE_GENERIC_WRITE):
                        offending_files.append(full_path)
        except:
            pass

    for offending_file in offending_files:
        reporter_output = ("A {} world-writable file was found."
                           " File: {}"
                           ).format(os.name, offending_file)
        if os.name == 'nt':
            reporter.warn(reporter_output)
        else:
            reporter.fail(reporter_output)


def _has_permission(access, permission):
    return access & permission == permission


def _new_dacl_with_all_control():
    dacl = win32security.ACL()
    everyone, _, _ = win32security.LookupAccountName("", "Everyone")
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, everyone)
    return dacl


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_hidden_files(app, reporter):
    """Check that there are no hidden files or directories."""
    for base, dirs, files in os.walk(app.app_dir):
        for elem in dirs + files:
            if elem.startswith("."):
                if platform.system() == "Windows":
                    path = os.path.join(base, elem).replace(app.app_dir + '\\', "")
                else:
                    path = os.path.join(base, elem).replace(app.app_dir + "/", "")
                reporter_output = ("The following hidden files were found. File: {}"
                                   ).format(path)
                reporter.fail(reporter_output, path)


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
