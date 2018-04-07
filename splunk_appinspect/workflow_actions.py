# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import logging
# Custom Libraries
import workflow_actions_configuration_file

logger = logging.getLogger(__name__)


class WorkFlowAction:
    """Represents a custom workflow action."""

    def __init__(self, name):
        self.name = name
        self.args = {}


class WorkFlowActions:
    """Represents a workflow_actions.conf file
    from default/workflow_actions.conf."""

    def __init__(self, app):
        self.app = app
        self.file_path = app.get_filename('default', 'workflow_actions.conf')

    def configuration_file_exists(self):
        return self.app.file_exists('default', 'workflow_actions.conf')

    def get_configuration_file(self):
        return self.app.get_config('workflow_actions.conf',
                                   config_file=workflow_actions_configuration_file.WorkflowActionsConfigurationFile())

    def get_workflow_actions(self):
        actions = []

        for section in self.get_configuration_file().section_names():
            action = WorkFlowAction(section)

            for key, value in self.get_configuration_file().items(section):
                action.args[key] = [value]

            yield action
