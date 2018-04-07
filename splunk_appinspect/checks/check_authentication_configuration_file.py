# Copyright 2017 Splunk Inc. All rights reserved.

"""
### authentication.conf File Standards

Ensure that bindDNpassword is not specified.

- [authentication.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Authenticationconf)
"""

# Python Standard Library
import logging
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.5.0")
def check_authentication_conf_does_not_have_bindDNPassword_property(app, reporter):
    """Check that stanzas in `authentication.conf` do not use the the
    bindDNpassword property.
    """
    if app.file_exists("default", "authentication.conf"):
        authentication_conf_file = app.authentication_conf()
        stanzas_with_bindDNpassword = [stanza_name
                                       for stanza_name
                                       in authentication_conf_file.section_names()
                                       if authentication_conf_file.has_option(stanza_name, "bindDNpassword")]
        if stanzas_with_bindDNpassword:
            for stanza_name in stanzas_with_bindDNpassword:
                reporter_output = ("authentication.conf contains the"
                                   " property bindDNpassword. Plain text"
                                   " credentials should never be included in an"
                                   " app. Please remove the bindDNpassword="
                                   " property. Stanza: [{}]. File:"
                                   " default/authentication.conf"
                                   .format(stanza_name))
                reporter.fail(reporter_output)
    else:
        reporter_output = ("authentication.conf does not exist.")
        reporter.not_applicable(reporter_output)
