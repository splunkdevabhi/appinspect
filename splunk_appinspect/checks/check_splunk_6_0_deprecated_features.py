# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 6.0

The following features should not be supported in Splunk 6.0 or later.
"""

# Python Standard Libraries
import os
# Custom Libraries
import splunk_appinspect

@splunk_appinspect.tags("splunk_appinspect", "splunk_6_0", "deprecated_feature", "cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_for_viewstates_conf(app, reporter):
    """Check that default/viewstates.conf does not exist in the app.
    (http://docs.splunk.com/Documentation/Splunk/6.0/AdvancedDev/Migration#Viewstates_are_no_longer_supported_in_simple_XML)
    """
    path = os.path.join("default", "viewstates.conf")
    if app.file_exists(path):
        reporter_output = ("There exists a default/viewstates.conf which is deprecated from Splunk 6.0.")
        reporter.warn(reporter_output, path)
    else:
        reporter_output = ("viewstates.conf does not exist.")
        reporter.not_applicable(reporter_output)