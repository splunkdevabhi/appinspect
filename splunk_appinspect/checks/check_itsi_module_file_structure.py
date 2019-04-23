# Copyright 2018 Splunk Inc. All rights reserved.

"""
### ITSI module file and folder structure verification

All the ITSI modules should follow the following file structure:
**splunk_home/etc/apps/*module_folder* - appserver[d] - static - default[d] - data[d] - models[d] - ui[d] - panels[d] - views[d] - app.conf[f] - deep_dive_drilldowns.conf[f] - inputs.conf[f] - itsi_kpi_base_search.conf[f] - itsi_kpi_template.conf[f] - itsi_module_viz.conf[f] - itsi_service_template.conf[f] - savedsearches.conf[f] - metadata[d] - default.meta[f]**

Test files should not be included with the package. For example, a directory such as **/etc/apps/*module_folder*/test** should not exist.
"""

# Python Standard Libraries
import logging
# Third-Party Libraries
# N/A
# Custom Libraries
import splunk_appinspect

report_display_order = 25
logger = logging.getLogger(__name__)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_appserver_folder_exist(app, reporter):
    """Check that the appserver/ directory exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.directory_exists("appserver"):
            reporter_output = ("The 'appserver' directory does not exist under the"
                               " module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_folder_exist(app, reporter):
    """Check that the default/ directory exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.directory_exists("default"):
            reporter_output = ("The 'default' directory does not exist under the"
                               " module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_metadata_folder_exist(app, reporter):
    """Check that the metadata/ directory exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.directory_exists("metadata"):
            reporter_output = ("The 'metadata' directory does not exist under the"
                               " module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_app_conf_file_exist(app, reporter):
    """Check that the default/app.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/app.conf"):
            reporter_output = ("The 'default / app.conf' file does not exist under"
                               " the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_deep_dive_drilldowns_conf_file_exist(app, reporter):
    """Check that the default/deep_dive_drilldowns.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/deep_dive_drilldowns.conf"):
            reporter_output = ("The 'default / deep_dive_drilldowns.conf' file does"
                               " not exist under the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_inputs_conf_file_exist(app, reporter):
    """Check that the default/inputs.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/inputs.conf"):
            reporter_output = ("The 'default / inputs.conf' file does not exist"
                               " under the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_itsi_service_template_conf_file_exist(app, reporter):
    """Check that default/itsi_service_template.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/itsi_service_template.conf"):
            reporter_output = ("The 'default / itsi_service_template.conf' file does not exist"
                               " under the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_itsi_kpi_base_search_conf_file_exit(app, reporter):
    """Check that the default/itsi_kpi_base_search.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/itsi_kpi_base_search.conf"):
            reporter_output = ("The 'default / itsi_kpi_base_search.conf' file does"
                               " not exist under the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_itsi_kpi_template_conf_file_exit(app, reporter):
    """Check that the default/itsi_kpi_template.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/itsi_kpi_template.conf"):
            reporter_output = ("The 'default / itsi_kpi_template.conf' file does"
                               " not exist under the module folder.")
            reporter.fail(reporter_output)


@splunk_appinspect.tags("itsi")
@splunk_appinspect.cert_version(min="1.14")
def check_default_savedsearches_conf_file_exit(app, reporter):
    """Check that the default/savedsearches.conf file exists."""
    if not valid_itsi_module(app):
        reporter.not_applicable("This is not an ITSI module.")
    else:
        if not app.file_exists("default/savedsearches.conf"):
            reporter_output = ("The 'default / savedsearches.conf' file does not"
                               " exist under the module folder.")
            reporter.fail(reporter_output)


def valid_itsi_module(app):
    return app.name.upper().startswith("DA-ITSI")
