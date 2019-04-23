# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Outputs.conf file standards

Ensure that the **outputs.conf** file located in the **/default** folder of the app is well formed and valid. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Outputsconf" target="_blank">outputs.conf</a>.
"""

# Python Standard Library
import logging
import os
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.splunk import normalizeBoolean


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.4")
def check_if_outputs_conf_exists(app, reporter):
    """Check that forwarding enabled in 'outputs.conf' is failed in cloud
    """
    config_file_paths = app.get_config_file_paths("outputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            outputs_conf = app.outputs_conf(directory)
            is_section_empty = is_default_disabled = True
            for section in outputs_conf.section_names():
                is_section_empty = False
                if outputs_conf.has_option(section, "disabled"):
                    is_default_disabled = False
                    is_disabled = normalizeBoolean(outputs_conf.get(section, "disabled"))
                    if is_disabled:
                        pass
                    else:
                        lineno = outputs_conf.get_section(section).get_option("disabled").lineno
                        reporter_output = ("From `{}/outputs.conf`, output is enabled."
                                            " This is prohibited in Splunk"
                                            " Cloud. Stanza: [{}]. File: {}, Line: {}."
                                           ).format(directory,
                                                    section,
                                                    file_path,
                                                    lineno)
                        reporter.fail(reporter_output, file_path, lineno)
            if not is_section_empty and is_default_disabled:
                reporter_output = ("From `{}/outputs.conf`, output is enabled"
                                    " by default `disabled = False`."
                                    " This is prohibited in Splunk"
                                    " Cloud. File: {}"
                                   ).format(directory,
                                            file_path)
                reporter.fail(reporter_output, file_path)

    else:
        reporter_output = ("`outputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)
