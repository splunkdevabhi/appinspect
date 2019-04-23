# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Alert actions structure and standards

Custom alert actions are defined in an **alert_actions.conf** file located in the **/default** directory of the app. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsIntro" target="_blank">Custom alert actions overview</a> and <a href="http://docs.splunk.com/Documentation/Splunk/latest/Admin/Alertactionsconf" target="_blank">alert_actions.conf</a>.
"""

# Python Standard Library
import itertools
import logging
import os
# Custom
import splunk_appinspect

report_display_order = 20

logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf')
@splunk_appinspect.cert_version(min='1.1.0')
def check_alert_actions_conf_exists(app, reporter):
    """Check that a valid `alert_actions.conf` file exists at
    default/alert_actions.conf.
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        pass
    else:
        reporter_output = "An alert_actions.conf does not exist in the app bundle."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf')
@splunk_appinspect.cert_version(min='1.1.1')
def check_alert_icon_exists_for_custom_alerts(app, reporter):
    """Check that icon files defined for alert actions in `alert_actions.conf`
    exist.
    [Custom Alert Action Component Reference](http://docs.splunk.com/Documentation/Splunk/6.3.0/AdvancedDev/ModAlertsCreate)
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = os.path.join('default', 'alert_actions.conf')
        for alert_action in alert_actions.get_alert_actions():
            if alert_action.icon_path:
                if alert_action.alert_icon().exists():
                    pass  # success, path is declared, file exists
                else:
                    lineno = alert_action.args['icon_path'][1]
                    reporter_output = ("The alert_actions.conf [{}] specified"
                                       " the icon_path value of {}, but did not"
                                       " find it. File: {}, Line: {}."
                                       ).format(alert_action.name,
                                                alert_action.icon_path,
                                                filename,
                                                lineno)
                    reporter.fail(reporter_output, filename, lineno)

            else:
                lineno = alert_action.lineno
                reporter_output = ("No icon_path was specified for [{}]. "
                                   "File: {}, Line: {}."
                                   ).format(alert_action.name, filename, lineno)
                reporter.fail(reporter_output, filename, lineno)
    else:
        reporter_output = ("No alert_actions.conf was found.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_alert_actions_exe_exist(app, reporter):
    """Check that each custom alert action has a valid executable."""

    # a) is there an overloaded cmd in the stanza e.g. execute.cmd
    # b) is there a file in default/bin for the files in nix_exes & windows_exes (one of each for platform agnostic)
    # c) is there a file in a specific arch directory for all

    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = os.path.join('default', 'alert_actions.conf')
        for alert in alert_actions.get_alert_actions():
            if alert.alert_execute_cmd_specified():
                # Highlander: There can be only one...
                if alert.executable_files[0].exists():
                    pass
                else:
                    lineno = alert.args['alert.execute.cmd'][1]
                    mess = ("No alert action executable for {} was found in the "
                            "bin directory. File: {}, Line: {}."
                            ).format(alert.alert_execute_cmd, filename, lineno)
                    reporter.fail(mess, filename, lineno)
            else:
                win_exes = alert.count_win_exes()
                linux_exes = alert.count_linux_exes()
                win_arch_exes = alert.count_win_arch_exes()
                linux_arch_exes = alert.count_linux_arch_exes()
                darwin_arch_exes = alert.count_darwin_arch_exes()

                # a) is there a cross plat file (.py, .js) in default/bin?
                if alert.count_cross_plat_exes() > 0:
                    continue

                # b) is there a file per plat in default/bin?
                if(win_exes > 0 or
                        linux_exes > 0):
                    continue

                # c) is there a file per arch?
                if(win_arch_exes > 0 or
                        linux_arch_exes > 0 or darwin_arch_exes > 0):
                    reporter_output = ("The specific architecture"
                                       " executables for the alert"
                                       " action {} should be"
                                       " verified. File: {}, Line: {}."
                                       ).format(alert.name, filename, alert.lineno)
                    reporter.manual_check(reporter_output, filename, alert.lineno)
                else:
                    reporter_output = ("No executable was found for alert"
                                       " action {}. File: {}, Line: {}."
                                       ).format(alert.name, filename, alert.lineno)
                    reporter.fail(reporter_output, filename, alert.lineno)
    else:
        reporter_output = ("No `alert_actions.conf` was detected.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf')
@splunk_appinspect.cert_version(min='1.1.0')
def check_workflow_html_exists_for_custom_alert(app, reporter):
    """Check that each custom alert action has an associated html file."""
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = os.path.join('default', 'alert_actions.conf')
        for alert in alert_actions.get_alert_actions():
            if not alert.workflow_html().exists():
                reporter_output = ("No HTML file was found at default/data/ui/alerts/"
                                   " for {}. File: {}, Line: {}."
                                   ).format(alert.workflow_html_path, filename, alert.lineno)
                reporter.fail(reporter_output, filename, alert.lineno)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_payload_format(app, reporter):
    """Check that each custom alert action's payload format has a value of `xml`
    or `json`.
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = os.path.join('default', 'alert_actions.conf')
        for alert in alert_actions.get_alert_actions():
            for arg in alert.args:
                if arg == "payload_format":
                    if(not alert.args["payload_format"][0] == "json" and
                            not alert.args["payload_format"][0] == "xml"):
                        lineno = alert.args['payload_format'][1]
                        reporter_output = ("The alert action must specify"
                                           " either 'json' or 'xml' as the"
                                           " payload. File: {}, Line: {}."
                                           ).format(filename, lineno)
                        reporter.fail(reporter_output, filename, lineno)


@splunk_appinspect.tags('splunk_appinspect', 'alert_actions_conf', 'manual')
@splunk_appinspect.cert_version(min='1.1.0')
def check_for_explict_exe_args(app, reporter):
    """Check whether any custom alert actions have executable arguments."""
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = os.path.join('default', 'alert_actions.conf')
        for alert in alert_actions.get_alert_actions():
            for arg in alert.args:
                if "alert.execute.cmd.arg" in arg:
                    lineno = alert.args[arg][1]
                    reporter_output = ("The alert action specifies executable arguments: "
                                       " {}, Manually verify these arguments"
                                       " against the executable."
                                       " File: {}, Line: {}."
                                       ).format(arg, filename, lineno)
                    reporter.manual_check(reporter_output, filename, lineno)
