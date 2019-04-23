# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Calls to external data sources
"""

# Python Standard Libraries
import logging
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)
report_display_order = 12


@splunk_appinspect.tags('splunk_appinspect', 'manual', 'appapproval')
@splunk_appinspect.cert_version(min='1.0.0')
def check_external_data_sources(app, reporter):
    """Check that all external data sources are explained in the app's
    documentation.
    """
    reporter.manual_check("Documentation will be read during code review.")
