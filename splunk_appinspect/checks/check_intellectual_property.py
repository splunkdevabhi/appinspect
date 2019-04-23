# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Intellectual property standards
"""

# Python Standard Libraries
import logging
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)
report_display_order = 3


@splunk_appinspect.tags('splunk_appinspect', 'manual', 'appapproval')
@splunk_appinspect.cert_version(min='1.0.0')
def check_splunk_logo(app, reporter):
    """Check that use of the Splunk logo and name meets Splunk
    [branding guidelines](http://docs.splunk.com/Documentation/Splunkbase/latest/Splunkbase/Namingguidelines).
    Customers should avoid using logos that are similar to the Splunk 
    logos including the splunk chevron. These are copyrighted items
    and should only be used by Splunk. Additionally apps built by 3rd 
    parties should not have names starting with Splunk.
    """
    reporter.manual_check("Branding will be inspected during code review.")
