# Copyright 2016 Splunk Inc. All rights reserved.

"""
### App.conf standards

The [app.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf)
file located at `default/app.conf` provides key application information and
branding.
"""

# Python Standard Library
import distutils.util
import logging
import re
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'appapproval')
@splunk_appinspect.cert_version(min='1.0.0')
def check_app_version(app, reporter):
    """Check that the `app.conf` contains an application version number in the
    [launcher] stanza.
    """
    if app.file_exists("default", "app.conf"):
        config = app.get_config('app.conf')

        try:
            config.has_option('launcher', 'version')
            version = config.get('launcher', 'version')

            reporter.assert_fail(re.match(r"^\d{1,3}.\d{1,3}(.\d{1,3})(\s?\w[\w\d]{,9})?$", version),
                                 "Major, minor, build version numbering is required.")

        except splunk_appinspect.configuration_file.NoOptionError:
            reporter.fail("No version specified in launcher section of app.conf.", file_name="default/app.conf")

        except splunk_appinspect.configuration_file.NoSectionError:
            reporter.fail("No launcher section found in app.conf.", file_name="default/app.conf")
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.20")
def check_that_setup_has_not_been_performed(app, reporter):
    """Check that `default/app.conf` setting `is_configured` = False."""
    if app.file_exists("default", "app.conf"):
        app_conf = app.app_conf()
        if (app_conf.has_section("install") and
                app_conf.has_option("install", "is_configured")):
            # Sets to either 1 or 0
            is_configured = distutils.util.strtobool(app_conf.get("install",
                                                                  "is_configured"))
            if is_configured:
                reporter_output = ("The app.conf [install] stanza has the"
                                   " `is_configured` property set to true."
                                   " This indicates a setup was already"
                                   " performed.")
                reporter.fail(reporter_output, file_name="default/app.conf")
            else:
                pass  # Pass - The property is true
        else:
            pass  # Pass - The stanza or property does not exist.
    else:
        reporter_output = ("`default/app.conf` does not exist.")
        reporter.not_applicable(reporter_output)
