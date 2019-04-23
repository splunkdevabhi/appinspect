# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Authentication.conf file standards

Ensure that `bindDNpassword` is not specified. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Authenticationconf" target="_blank">authentication.conf</a>.
"""

# Python Standard Library
import logging
import os
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk import normalizeBoolean

logger = logging.getLogger(__name__)


@splunk_appinspect.tags("splunk_appinspect")
@splunk_appinspect.cert_version(min="1.5.0")
def check_authentication_conf_does_not_have_bindDNPassword_property(app, reporter):
    """Check that stanzas in `authentication.conf` do not use the the
    bindDNpassword property.
    """
    config_file_paths = app.get_config_file_paths("authentication.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            authentication_conf_file = app.authentication_conf(dir=directory)
            stanzas_with_bindDNpassword = [stanza_name
                                           for stanza_name
                                           in authentication_conf_file.section_names()
                                           if authentication_conf_file.has_option(stanza_name, "bindDNpassword")]
            if stanzas_with_bindDNpassword:
                for stanza_name in stanzas_with_bindDNpassword:
                    lineno = authentication_conf_file.get_section(stanza_name).get_option("bindDNpassword").lineno
                    reporter_output = ("authentication.conf contains the"
                                       " property bindDNpassword. Plain text"
                                       " credentials should not be included in an"
                                       " app. Please remove the bindDNpassword="
                                       " property. Stanza: [{}]. File: {}, Line: {}."
                                       .format(stanza_name,
                                               file_path,
                                               lineno))
                    reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter_output = "authentication.conf does not exist."
        reporter.not_applicable(reporter_output)


# ACD-2339
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.6.0")
def check_saml_auth_should_not_turn_off_signed_assertion(app, reporter):
    """Check that saml-* stanzas in `authentication.conf` do not turn off signedAssertion property
    """
    config_file_paths = app.get_config_file_paths("authentication.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            authentication_conf_file = app.authentication_conf(dir=directory)
            has_auth_type = authentication_conf_file.has_option('authentication', 'authType')
            if has_auth_type and authentication_conf_file.get('authentication', 'authType') == 'SAML':
                _report_failure_for_saml_stanza_with_signed_assertion_off(directory, authentication_conf_file, reporter)

    else:
        reporter_output = "authentication.conf does not exist."
        reporter.not_applicable(reporter_output)


def _report_failure_for_saml_stanza_with_signed_assertion_off(directory, auth_conf, reporter):
    stanzas_with_signed_assertion = [(section.name, section.lineno)
                                     for section in auth_conf.sections_with_setting_key_pattern('signedAssertion')
                                     if section.name.startswith('saml-') and _is_signed_assertion_off(section)]
    file_path = os.path.join(directory, "authentication.conf")
    for stanza_name, stanza_lineno in stanzas_with_signed_assertion:
        reporter_output = 'SAML signedAssertion property is turned off, whichi will introduce vulnerabilities. ' \
                          'Please turn the signedAssertion property on. ' \
                          'Stanza: [{}] ' \
                          'File: {}, ' \
                          'Line: {}.'.format(stanza_name, file_path, stanza_lineno)
        reporter.fail(reporter_output, file_path, stanza_lineno)


def _is_signed_assertion_off(section):
    return not normalizeBoolean(section.get_option('signedAssertion').value.strip())
