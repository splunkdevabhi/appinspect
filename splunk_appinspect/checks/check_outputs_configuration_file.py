# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Outputs.conf file standards

Ensure that the outputs.conf file located in the `default` folder is well formed
 and valid.

- [outputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Outputsconf)
"""

# Python Standard Library
import logging
# Custom Libraries
import splunk_appinspect


@splunk_appinspect.tags("splunk_appinspect", "appapproval", "manual")
@splunk_appinspect.cert_version(min="1.1.8")
def check_if_outputs_conf_exists(app, reporter):
    """Check that forwarding enabled in 'outputs.conf' is explained in the 
    app's documentation.
    """
    if app.file_exists("default", "outputs.conf"):
        reporter_output = ("Outputs.conf will be inspected during code review.")
        reporter.manual_check(reporter_output, 'default/outputs.conf')
    else:
        reporter.not_applicable("No outputs.conf found.")
