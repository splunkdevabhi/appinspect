# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Props Configuration file standards

Ensure that all props.conf files located in the `default` (or `local`) folder are well
formed and valid.

- [props.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf)
- [transforms.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf)
"""

# Python Standard Library
import logging
import re
import os
# Custom Libraries
import splunk_appinspect

report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_server_conf_only_contains_custom_conf_sync_stanzas_or_diag_stanza(app, reporter):
    """Check that server.conf in an app is only allowed to contain:
    1) conf_replication_include.<custom_conf_files> in [shclustering] stanza
    2) or EXCLUDE-<class> property in [diag] stanza
    """
    server_conf_existed = False
    for directory in ['default', 'local']:
        if app.file_exists(directory, "server.conf"):
            server_conf_existed = True
            file_path = os.path.join(directory, "server.conf")

            server_config = app.server_conf()

            for section in server_config.sections():
                if section.name == 'shclustering':
                    _check_disallow_settings(reporter, file_path, section, 'conf_replication_include\..*')
                elif section.name == 'diag':
                    _check_disallow_settings(reporter, file_path, section, 'EXCLUDE-.*')
                else:
                    reporter_output = "Stanza `[{}]` configures Splunk server settings " \
                                      "and is not permitted in Splunk Cloud. File: {}, Line: {}.".format(section.name,
                                                                                                         file_path,
                                                                                                         section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)

    if not server_conf_existed:
        reporter_output = "No server.conf file exists."
        reporter.not_applicable(reporter_output)


def _check_disallow_settings(reporter, file_path, section, allowed_settings_pattern):
    all_setting_names = [s.name for s in section.settings()]
    allowed_setting_names = _get_setting_names_with_key_pattern(section, allowed_settings_pattern)
    disallowed_settings = _get_disallowed_settings(all_setting_names, allowed_setting_names)
    if disallowed_settings:
        reporter_output = "Only {} properties are allowed " \
                          "for `[{}]` stanza. The properties {} are not allowed in this stanza. " \
                          "File: {}, Line: {}".format(allowed_settings_pattern, section.name,
                                                      disallowed_settings, file_path, section.lineno)
        reporter.fail(reporter_output, file_path, section.lineno)


def _get_setting_names_with_key_pattern(section, pattern):
    return [s.name for s in section.settings_with_key_pattern(pattern)]


def _get_disallowed_settings(setting_names, allowed_settings):
    return set(setting_names).difference(set(allowed_settings))
