# Copyright 2018 Splunk Inc. All rights reserved.

"""
### App.conf standards

The **app.conf** file located at **default/app.conf** provides key application information and branding. For more, see <a href='https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf' target='_blank'>app.conf</a>.
"""

# Python Standard Library
import logging
import re
import os
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk import normalizeBoolean
from splunk_appinspect.app_util import AppVersionNumberMatcher

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval','prerelease')
@splunk_appinspect.cert_version(min='1.0.0')
def check_app_version(app, reporter):
    """Check that the `app.conf` contains an application version number in the
    [launcher] stanza.
    """
    if app.file_exists("default", "app.conf"):
        filename = os.path.join('default', 'app.conf')
        config = app.get_config('app.conf')
        matcher = AppVersionNumberMatcher()

        try:
            config.has_option('launcher', 'version')
            version = config.get('launcher', 'version')
            if len(matcher.match(version)) == 0:
                lineno = config.get_section('launcher').get_option('version').lineno
                reporter_output = ("Major, minor, build version numbering "
                                   "is required. File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.warn(reporter_output, filename, lineno)

        except splunk_appinspect.configuration_file.NoOptionError:
            lineno = config.get_section('launcher').lineno
            reporter_output = ("No version specified in launcher section "
                               "of app.conf. File: {}, Line: {}."
                               ).format(filename, lineno)
            reporter.fail(reporter_output, filename, lineno)

        except splunk_appinspect.configuration_file.NoSectionError:
            reporter_output = ("No launcher section found in app.conf. "
                               "File: {}"
                               ).format(filename)
            reporter.warn(reporter_output, file_name=filename)
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.20")
def check_that_setup_has_not_been_performed(app, reporter):
    """Check that `default/app.conf` setting `is_configured` = False."""
    if app.file_exists("default", "app.conf"):
        filename = os.path.join('default', 'app.conf')
        app_conf = app.app_conf()
        if (app_conf.has_section("install") and
                app_conf.has_option("install", "is_configured")):
            # Sets to either 1 or 0
            is_configured = normalizeBoolean(app_conf.get("install", "is_configured"))
            if is_configured:
                lineno = app_conf.get_section('install').get_option('is_configured').lineno
                reporter_output = ("The app.conf [install] stanza has the"
                                   " `is_configured` property set to true."
                                   " This property indicates that a setup was already"
                                   " performed. File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
            else:
                pass  # Pass - The property is true
        else:
            pass  # Pass - The stanza or property does not exist.
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags('splunk_appinspect')
@splunk_appinspect.cert_version(min='1.6.0')
def check_for_invalid_app_names(app, reporter):
    """Check that `default/app.conf` has `author = <some words are not about Splunk>` must not
    has attributes `label` or `description` with values of `Splunk App for XXXX`.
    """
    if app.file_exists("default", "app.conf"):
        filename = os.path.join('default', 'app.conf')
        app_conf = app.app_conf()
        is_author_splunk = _is_author_splunk(app_conf)
        if app_conf.has_option("ui", "label"):
            name = app_conf.get("ui", "label")
            if _is_with_value_of_splunk_app_for(name) and not is_author_splunk:
                lineno = app_conf.get_section('ui').get_option('label').lineno
                reporter_output = ("For the app.conf [ui] stanza's 'label' attribute,"
                                   " names of community-built apps must not start with 'Splunk'."
                                   " For example 'Splunk app for Awesome' is inappropriate,"
                                   " but 'Awesome app for Splunk' is OK. File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
        if app_conf.has_option("launcher", "description"):
            name = app_conf.get("launcher", "description")
            if _is_with_value_of_splunk_app_for(name) and not is_author_splunk:
                lineno = app_conf.get_section('launcher').get_option('description').lineno
                reporter_output = ("For the app.conf [launcher] stanza's 'description' attribute,"
                                   " apps built by 3rd parties should not have names starting with Splunk."
                                   " For example 'Splunk app for Awesome' is inappropriate,"
                                   " but 'Awesome app for Splunk' is OK. File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)

def _is_with_value_of_splunk_app_for(name):
    # the regex expression is for searching:
    # "splunk (addon|add on|add-on|app)s for"
    return True if re.search(r'splunk\s*(add(\s*|-*)on|app)(s*)\s*for', name, re.IGNORECASE) else False

def _is_author_splunk(app_conf):
    if app_conf.has_option("launcher", "author"):
        if re.search(r'splunk', app_conf.get("launcher", "author"), re.IGNORECASE):
            return True
    for name in app_conf.section_names():
        if re.search(r'author=', name):
            if re.search(r'splunk', name, re.IGNORECASE):
                return True
            else:
                if app_conf.has_option(name, "company"):
                    return True if re.search(r'splunk', app_conf.get(name,"company"), re.IGNORECASE) else False
    return False

@splunk_appinspect.tags('splunk_appinspect', 'cloud')
@splunk_appinspect.cert_version(min='1.6.0')
def check_no_install_source_checksum(app, reporter):
    """Check in `default/app.conf`, install_source_checksum not be set explicitly."""
    if app.file_exists("default", "app.conf"):
        filename = os.path.join('default', 'app.conf')
        app_conf = app.app_conf()
        if (app_conf.has_section("install") and
                app_conf.has_option("install", "install_source_checksum")):
            install_source_checksum = app_conf.get("install", "install_source_checksum")
            if install_source_checksum:
                lineno = app_conf.get_section('install').get_option('install_source_checksum').lineno
                reporter_output = ("For the app.conf [install] stanza's `install_source_checksum` attribute,"
                                   " it records a checksum of the tarball from which a given app was installed."
                                   " Splunk Enterprise will automatically populate this value during installation."
                                   " Developers should *not* set this value explicitly within their app! File: {}, Line: {}."
                                   ).format(filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
            else:
                pass  # Pass - The property is empty.
        else:
            pass  # Pass - The stanza or property does not exist.
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)
