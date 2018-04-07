# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Custom workflow actions structure and standards

[Custom workflow actions](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions)
are defined in
[workflow_actions.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Workflow_actionsconf)
located at `default/workflow_actions.conf`.
"""

# Python Standard Library
import logging
import re
# Custom Modules
import splunk_appinspect

logger = logging.getLogger(__name__)

report_display_order = 20


@splunk_appinspect.tags('splunk_appinspect', 'custom_workflow_actions')
@splunk_appinspect.cert_version(min='1.1.7')
def check_workflow_actions_conf_exists(app, reporter):
    """Check that a valid `workflow_actions.conf` file exists at
    `default/workflow_actions.conf`.
    """
    workflow_actions = app.get_workflow_actions()
    if workflow_actions.configuration_file_exists():
        pass
    else:
        reporter_output = ("The 'workflow_actions.conf' does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'custom_workflow_actions')
@splunk_appinspect.cert_version(min='1.1.7')
def check_required_stanza_fields_are_specified(app, reporter):
    """Check that stanzas in `workflow_actions.conf.spec` have the required
    fields, type, and label.
    """
    workflow_actions = app.get_workflow_actions()
    if workflow_actions.configuration_file_exists():
        for action in workflow_actions.get_workflow_actions():

            if "type" not in action.args:
                reporter_output = ("The stanza [{}] does not specify 'type'."
                                   ).format(action.name)
                reporter.fail(reporter_output)

            if "label" not in action.args:
                reporter_output = ("The stanza [{}] does not specify 'label'."
                                   ).format(action.name)
                reporter.fail(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_workflow_actions_link_uri_does_not_use_http_protocol(app, reporter):
    """Check that for each workflow action in `workflow_actions.conf` the
    link.uri property uses the https protocol for external links. Unencrypted
    http is permitted for internal links.
    """
    if app.file_exists("default", "workflow_actions.conf"):
        workflow_actions = app.get_workflow_actions()

        workflow_actions_with_link_uri = [workflow_action
                                          for workflow_action
                                          in workflow_actions.get_workflow_actions()
                                          if "link.uri" in workflow_action.args]
        for workflow_action in workflow_actions_with_link_uri:
            link_uris = workflow_action.args["link.uri"]
            for link_uri in link_uris:
                link_uri = link_uri.strip()
                # Internal links (to the local server) are permitted to be HTTP,
                # external links must use HTTPS
                if (link_uri.startswith("/") or link_uri.startswith("http://localhost") or
                    link_uri.startswith("http://127.0.0.1") or
                    link_uri.startswith("localhost") or link_uri.startswith("127.0.0.1") or
                    link_uri.startswith("https://")):
                    pass
                else:
                    reporter_output = ("The workflow action [{}] link.uri"
                                       " property appears to be an external"
                                       " link that is unencrypted. Please"
                                       " change `{}` to use https://"
                                       ).format(workflow_action.name, link_uri)
                    reporter.fail(reporter_output)
    else:
        reporter_output = ("`workflow_actions.conf` does not exist.")
        reporter.not_applicable(reporter_output)
