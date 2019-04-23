# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Javascript file standards
"""

# Python Standard Library
import logging
import os
import re
# Third-Party
from bs4 import BeautifulSoup
from lxml import etree
# N/A
# Custom Modules
import splunk_appinspect
from splunk_appinspect.regex_matcher import JSInsecureHttpRequestMatcher
from splunk_appinspect.regex_matcher import JSIFrameMatcher
from splunk_appinspect.regex_matcher import JSConsoleLogMatcher
from splunk_appinspect.regex_matcher import JSRemoteCodeExecutionMatcher
from splunk_appinspect.regex_matcher import JSWeakEncryptionMatcher
from splunk_appinspect.regex_matcher import JSUDPCommunicationMatcher
from splunk_appinspect.regex_matcher import ConfEndpointMatcher

from splunk_appinspect.reflected_xss_detector import ReflectedXSSDetector

logger = logging.getLogger(__name__)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_insecure_http_request_in_javascript(app, reporter):
    """Check if the app contain possible insecure http request in javascript files."""
    matcher = JSInsecureHttpRequestMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
            app.app_dir, app.iterate_files(types=['.js']), regex_option=re.IGNORECASE):
        reporter_output = ("The following line will be inspected during code review."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(result, file_path, lineno)
        reporter.manual_check(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "No javascript files found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_iframe_in_javascript(app, reporter):
    """Check if the app contains possible iframe in javascript files, templates or html pages."""
    javascript_files = list(app.iterate_files())  # check all files instead of specific suffixes

    if javascript_files:
        matcher = JSIFrameMatcher()
        for directory, filename, ext in javascript_files:
            file_path = os.path.join(directory, filename)
            full_file_path = app.get_filename(file_path)

            match_result = matcher.match_file(filepath=full_file_path, regex_option=re.IGNORECASE)
            result_dict = {}

            for lineno, result in match_result:
                if re.search('src=["\'](javascript:(0|false|void\(0\)|""|\'\')?|about:blank)["\']', result):
                    continue
                if lineno not in result_dict:
                    result_dict[lineno] = set()
                result_dict[lineno].add(result)
            for lineno, result_set in result_dict.items():
                for result in result_set:
                    reporter_output = ("The following line will be inspected during code review."
                                       " Match: {}"
                                       " File: {}"
                                       " Line: {}"
                                       ).format(result, file_path, lineno)
                    reporter.manual_check(reporter_output, file_path, lineno)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_console_log_injection_in_javascript(app, reporter):
    """ Check if any sensitive data leakage in console log"""
    matcher = JSConsoleLogMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
            app.app_dir, app.iterate_files(types=['.js']),
            regex_option=re.IGNORECASE,
            excluded_comments=False):
        reporter_output = ("The following line will be inspected during code review."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(result, file_path, lineno)
        reporter.manual_check(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "No javascript files found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_remote_code_execution_in_javascript(app, reporter):
    """Check if the app contain possible remote code execution in javascript files."""
    matcher = JSRemoteCodeExecutionMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
            app.app_dir, app.iterate_files(types=['.js'])):
        reporter_output = ("The following line will be inspected during code review."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(result, file_path, lineno)
        reporter.manual_check(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "No javascript files found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'splunk-appinspect', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_weak_encryption_and_hashing_in_javascript(app, reporter):
    """ Check if any weak encryption in javascript"""
    matcher = JSWeakEncryptionMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
            app.app_dir, app.iterate_files(types=['.js'])):
        reporter_output = ("The following line will be inspected during code review."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(result, file_path, lineno)
        reporter.manual_check(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "No javascript files found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_udp_communication_in_javascript(app, reporter):
    """Check if the app contains udp communication in javascript files."""
    matcher = JSUDPCommunicationMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
            app.app_dir, app.iterate_files(types=['.js'])):
        reporter_output = ("The following line will be inspected during code review."
                           " Match: {}"
                           " File: {}"
                           " Line: {}"
                           ).format(result, file_path, lineno)
        reporter.manual_check(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "No javascript files found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_stored_xss_in_javascript(app, reporter):
    """ Check if possible stored xss in javascript """
    '''
        setup.xml -> read conf -> src(covered in reflected xss)
        # TODO check stored xss dynamically
    '''
    if app.file_exists("default", "setup.xml"):
        setup_full_filepath = app.get_filename("default", "setup.xml")
        root = etree.parse(setup_full_filepath)
        conf_endpoints = [b.attrib['endpoint'].split('/')[-1] for b in root.iter("block") if 'endpoint' in b.attrib]
        if conf_endpoints:
            matcher = ConfEndpointMatcher()
            for result, file_path, lineno in matcher.match_results_iterator(
                    app.app_dir,
                    app.iterate_files(types=['.js', '.html']),
                    regex_option=re.IGNORECASE):
                if any([True if endpoint in result else False for endpoint in conf_endpoints]):
                    reporter_output = ("Please manually check the configurations in setup.xml. "
                                       "Stored configurations that accept user input might be processed in JavaScript code,"
                                       " which poses a potential stored XSS threat."
                                       " Match: {}"
                                       " File: {}"
                                       " Line: {}"
                                       ).format(result, file_path, lineno)
                    reporter.manual_check(reporter_output, file_path, lineno)
    else:
        reporter_output = "`default/setup.xml` does not exist. The stored xss check is not applicable"
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_reflected_xss_in_javascript(app, reporter):
    """ Check if possible reflected xss in javascript """
    detector = ReflectedXSSDetector(app)
    detect_result = detector.detect()
    for result in detect_result:
        if len(result) == 2:
            reporter.manual_check(message=result[0], file_name=result[1])
        elif len(result) == 3:
            reporter.manual_check(message=result[0], file_name=result[1], line_number=result[2])
        else:
            reporter.manual_check(message=result[0])