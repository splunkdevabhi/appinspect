# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Platform targets and claimed supported Splunk versions
"""

# Claimed Platform Targets: App must run against claimed supported Splunk
# versions.
# Python Standard Libraries
import logging
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
        reporter.not_applicable("File: app.manifest was found, skipping this check.")
    elif app.file_exists("default/setup.xml"):
        reporter.manual_check("File: default/setup.xml exists, so manual setup in a distributed environment is required.", "default/setup.xml")
    elif setup_view_option_found:
        reporter.manual_check("File: Custom setup.xml exists, so manual setup in a distributed environment is required.")
