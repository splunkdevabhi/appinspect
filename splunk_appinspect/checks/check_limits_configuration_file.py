# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Limits.conf file standards

Ensure that `default/limits.conf` is omitted.

Including `limits.conf` within an app changes the limits that are placed on the
system for hardware use and memory consumption. This should be handled by Splunk
Administrators and not Splunk App Developers, thus including a `limits.conf`
file is prohibited.

- [limits.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Limitsconf)
"""

# Python Standard Library
import logging
# Custom Libraries
import splunk_appinspect


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=6)
def check_limits_conf(app, reporter):
    """Check that `default/limits.conf` has not been included."""
    if app.file_exists("default", "limits.conf"):
        reporter_output = ("Changes to 'limits.conf' are not allowed. Hardware"
                           " and memory limits should be left to Splunk"
                           " Administrators. Please remove this file:"
                           " default/limits.conf.")
        reporter.fail(reporter_output)
