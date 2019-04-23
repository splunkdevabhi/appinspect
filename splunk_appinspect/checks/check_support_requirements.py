# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Support requirements
"""

# Python Standard Libraries
import logging
# Custom Libraries
import splunk_appinspect

report_display_order = 60
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'manual', 'appapproval', 'markdown')
@splunk_appinspect.cert_version(min='1.0.0')
@splunk_appinspect.display(report_display_order=10)
def check_link_includes_contact_info(app, reporter):
    """Check that the app's documentation lists contact information and level
    of support for the app.  Any level of support is acceptable for developer
    supported apps, as long as it is clearly declared in documentation.
    Community supported apps must be open source with a public repository.
    For example:
    * Email support during weekday business hours (US, West Coast).
    * Phone support 24x7 @ +1 (555) 123-4567.
    * This is an open source project, no support provided, public repository
    available.
    """
    reporter.manual_check("Documentation will be read during code review.")
