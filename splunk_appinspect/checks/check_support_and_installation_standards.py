# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Platform targets and claimed supported Splunk Enterprise versions
"""

# Claimed Platform Targets: App must run against claimed supported Splunk
# versions.
# Python Standard Libraries
import logging
import os
import re
# Custom Libraries
import splunk_appinspect

report_display_order = 6
logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'manual', 'appapproval')
@splunk_appinspect.cert_version(min='1.0.0')
def check_install_on_claimed_targets(app, reporter):
    """Check that the app installs on all claimed target platforms."""
    reporter.manual_check("App will be checked during code review.")


@splunk_appinspect.tags('cloud', 'splunk_appinspect', 'self-service', 'manual')
@splunk_appinspect.cert_version(min="1.5.0")
def check_setup_in_distributed_environment(app, reporter):
    """Check that the app can be setup on a distributed system after
    self-service. Warn if setup configures non-search-head features like
    inputs. This makes the app incompatible with distributed environments.
    """
    setup_view_option_found = False
    app_conf = app.app_conf()
    if app_conf.has_section("ui"):
        ui_section = app_conf.get_section("ui")
        setup_view_option_found = ui_section.has_option("setup_view")

    if app.file_exists("app.manifest"):
        reporter.not_applicable("File: app.manifest was found. Skipping this check.")

    elif app.file_exists("default/setup.xml"):
        file_path = os.path.join("default", "setup.xml")
        sp = app.setup_xml()
        try:
            if sp and (sp.parse('xml').find_all('block', endpoint=re.compile('.*/inputs/.*')) \
                    or sp.parse('xml').find_all('input', endpoint=re.compile('.*/inputs/.*'))):
                reporter_output = ("Inputs configuration in default/setup.xml "
                                   "are not supported in distributed environments. "
                                   "File: {} "
                                   ).format(file_path)
                reporter.warn(reporter_output, file_path)
            else:
                reporter_output = ("default/setup.xml exists, so manual setup in a distributed environment"
                                   " is required. File: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
        except Exception, e:
            reporter_output = ("Failed to parse the file: default/setup.xml. This file might be formatted incorrectly."
                               "Exceptions: {}. File: {}"
                               ).format(str(e),
                                        file_path)
            reporter.fail(reporter_output, file_path)

    elif setup_view_option_found:
        # there exists only one custom setup view page, so if xml, no html; otherwise, no xml 
        custom_setup_name = ui_section.get_option("setup_view").value
        has_xml_file = app.file_exists("default/data/ui/views/{}.xml".format(custom_setup_name))
        has_html_file = app.file_exists("default/data/ui/html/{}.html".format(custom_setup_name))
        if has_xml_file or has_html_file:
            file_path = os.path.join("default", "data", "ui", "views", "{}.xml".format(custom_setup_name)) if has_xml_file else \
                        os.path.join("default", "data", "ui", "html", "{}.html".format(custom_setup_name))
            try:
                # For html setup view page, we report it as a manual check 
                sp = app.custom_setup_view_xml(custom_setup_name) if has_xml_file else None
                if sp and (sp.parse('xml').find_all('block', endpoint=re.compile('.*/inputs/.*')) \
                        or sp.parse('xml').find_all('input', endpoint=re.compile('.*/inputs/.*'))):
                    reporter_output = ("Inputs configuration in default/data/ui/views/{}.xml are not supported in distributed"
                                       " environments. File: {}"
                                       ).format(custom_setup_name,
                                                file_path)
                    reporter.warn(reporter_output, file_path)
                else:
                    reporter_output = ("Custom setup page exists, "
                                       "so manual setup in a distributed environment is required. "
                                       "File: {}"
                                       ).format(file_path)
                    reporter.manual_check(reporter_output, file_path)

            except Exception, e:
                reporter_output = ("Failed to parse the file: {}, so it might be formatted incorrectly."
                                   "Exceptions: {}, File: {}"
                                   ).format(file_path,
                                            str(e),
                                            file_path)
                reporter.fail(reporter_output, file_path)
        else:
            # this checkpoint should have been covered in separate check
            file_path = os.path.join("default", "app.conf")
            reporter_output = ("Custom setup page {} is not found in default/data/ui. File: {}"
                                ).format(custom_setup_name, 
                                         file_path)
            reporter.fail(reporter_output, file_path)
