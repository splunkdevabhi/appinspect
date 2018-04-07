# Copyright 2016 Splunk Inc. All rights reserved.

"""
### Cloud Operations Simple Application Check

This group serves to help validate simple applications in an effort to try and
automate the cloud operations validation process.
"""

# Python Standard Libraries
import logging
import os
import platform
import re
import subprocess
# Third-Party Libraries
import bs4
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.documentation import DocumentationLinks
from splunk_appinspect.lookup import LookupHelper

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# White List Checks Go Here
# ------------------------------------------------------------------------------
@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_unrecognized_default_files(app, reporter):
    """Check for any files in `default/` not covered by
    other checks for Splunk Cloud.
    """
    recognized_files = [
        # a
        "addon_builder.conf",                # safe
        "alert_actions.conf",                # checked in check_alert_actions_conf_for_alert_execute_cmd_properties
        "app.conf",                          # safe
        "audit.conf",                        # blacklisted
        "authentication.conf",               # blacklisted
        "authorize.conf",                    # checked in check_authorize_conf_admin_all_objects_privileges
        # c
        "checklist.conf",                    # safe
        "collections.conf",                  # safe
        "crawl.conf",                        # blacklisted
        # d
        "datatypesbnf.conf",                 # blacklisted
        "datamodels.conf",                   # checked in check_data_models_config.check_for_datamodel_acceleration
        "default.meta.conf",                 # safe
        "default-mode.conf",                 # blacklisted
        "deployment.conf",                   # blacklisted
        "deploymentclient.conf",             # blacklisted
        # e
        "eventdiscoverer.conf",              # safe
        "eventgen.conf",                     # safe
        "eventtypes.conf",                   # safe
        "event_renderers.conf",              # safe
        # f
        "fields.conf",                       # safe
        # i
        "indexes.conf",                      # checked in check_indexes_conf_only_uses_splunk_db_variable
        "inputs.conf",                       # checked in check_only_encrypted_inputs_are_used
        "instance.cfg.conf",                 # blacklisted
        # l
        "limits.conf",                       # blacklisted
        "literals.conf",                     # blacklisted
        # m
        "macros.conf",                       # safe
        "messages.conf",                     # blacklisted
        "multikv.conf",                      # safe
        # o
        "outputs.conf",                      # blacklisted
        # p
        "passwords.conf",                    # safe
        "procmon-filters.conf",              # safe
        "props.conf",                        # safe
        "pubsub.conf",                       # blacklisted
        # r
        "readme.txt",                        # safe
        # s
        "savedsearches.conf",                # checked in check_for_real_time_saved_searches
        "searchbnf.conf",                    # safe
        "segmenters.conf",                   # blacklisted
        "server.conf",                       # blacklisted
        "serverclass.conf",                  # blacklisted
        "serverclass.seed.xml.conf",         # blacklisted
        "setup.xml",                         # safe
        "source-classifier.conf",            # blacklisted
        "sourcetypes.conf",                  # blacklisted
        "splunk-launch.conf",                # blacklisted
        # t
        "tags.conf",                         # safe
        "telemetry.conf",                    # blacklisted
        "times.conf",                        # safe
        "transactiontypes.conf",             # safe
        "transforms.conf",                   # safe
        # u
        "ui-prefs.conf",                     # safe
        "ui-tour.conf",                      # safe
        "user-prefs.conf",                   # safe
        "user-seed.conf",                    # blacklisted
        # v
        "viewstates.conf",                   # safe
        "visualizations.conf",               # safe
        # w
        "web.conf",                          # checked in check_web_conf
        "wmi.conf",                          # blacklisted
        "workflow_actions.conf"              # checked in check_workflow_actions_link_uri_are_https
    ]
    recognized_directories = [
        # checked in check_default_data_ui_alerts_directory_file_white_list
        os.path.join("default", "data", "ui", "alerts", ""),
        # checked in check_default_data_ui_html_directory_file_white_list
        os.path.join("default", "data", "ui", "html", ""),
        # checked in check_default_data_ui_manager_directory_file_white_list
        os.path.join("default", "data", "ui", "manager", ""),
        # checked in check_default_data_ui_nav_directory_file_white_list
        os.path.join("default", "data", "ui", "nav", ""),
        # checked in check_default_data_ui_panels_directory_file_white_list
        os.path.join("default", "data", "ui", "panels", ""),
        # checked in check_default_data_ui_quickstart_directory_file_white_list
        os.path.join("default", "data", "ui", "quickstart", ""),
        # checked in check_default_data_ui_views_directory_file_white_list
        os.path.join("default", "data", "ui", "views", "")
    ]
    links = DocumentationLinks()
    if app.directory_exists("default"):
        for directory, filename, ext in app.iterate_files(basedir="default"):
            if directory not in recognized_directories:
                file_path = os.path.join(directory, filename)
                if filename not in recognized_files:
                    doc_link = links.get_splunk_docs_link(filename)
                    reporter_output = ("Please investigate this file: {}. {}"
                                       ).format(file_path, doc_link)
                    reporter.manual_check(reporter_output, file_path)
    else:
        reporter_output = "The `default` directory does not exist."

        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_views_directory_file_white_list(app, reporter):
    """Check that `default/data/ui/views` contains only allowed files."""
    allowed_file_types = [".html", ".xml"]
    allowed_filenames = ["README"]
    if app.directory_exists("default", "data", "ui", "views"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/views"):
            if(ext not in allowed_file_types and
               filename not in allowed_filenames):
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/views` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_panels_directory_file_white_list(app, reporter):
    """Check that `default/data/ui/panels` contains only .xml or .html files."""
    allowed_file_types = [".html", ".xml"]
    if app.directory_exists("default", "data", "ui", "panels"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/panels"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/panels` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_nav_file_white_list(app, reporter):
    """Check that `default/data/ui/nav` contains only .xml or .html files."""
    allowed_file_types = [".html", ".xml"]
    if app.directory_exists("default", "data", "ui", "nav"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/nav"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/nav` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_html_file_white_list(app, reporter):
    """Check that `default/data/ui/html` contains only .xml or .html files."""
    allowed_file_types = [".html", ".xml"]
    if app.directory_exists("default", "data", "ui", "html"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/html"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/html` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_alerts_file_white_list(app, reporter):
    """Check that `default/data/ui/alerts` contains only .xml or .html files."""
    allowed_file_types = [".html", ".xml"]
    if app.directory_exists("default", "data", "ui", "alerts"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/alerts"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/alerts` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_quickstart_file_white_list(app, reporter):
    """Check that `default/data/ui/quickstart` contains only .xml or .html
    files.
    """
    allowed_file_types = [".html", ".xml"]
    if app.directory_exists("default", "data", "ui", "quickstart"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/quickstart"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/quickstart` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_manager_file_white_list(app, reporter):
    """Check `default/data/ui/manager` for any files that configure modular
    inputs, communicate unencrypted data, or store plain text credentials.
    """
    allowed_file_types = []
    if app.directory_exists("default", "data", "ui", "manager"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/manager"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file to ensure that"
                                   " it does not configure modular inputs,"
                                   " communicate unencrypted data, or store"
                                   " plain text credentials: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `default/data/ui/manager` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.19")
def check_lookups_white_list(app, reporter):
    """Check that `lookups/` contains only approved file types (.csv,
    .csv.default, .csv.gz, .csv.tgz, .kmz) or files formatted as valid csv."""
    allowed_file_types = [".csv", ".csv.default", ".csv.gz", ".csv.tgz", ".kmz"]
    if app.directory_exists("lookups"):
        for directory, filename, ext in app.iterate_files(basedir="lookups"):
            # if ext not in allowed_file_types:
            # Pretty messy way to determine if the allowed extension is a dotted
            # file, on account that iterate files will only return the last
            # level of the extension I.E. .csv.gz returns .gz instead of
            # .csv.gz
            does_file_name_end_with_extension = len([True
                                                     for allowed_file_type
                                                     in allowed_file_types
                                                     if filename.endswith(allowed_file_type)]) > 0
            if not does_file_name_end_with_extension:
                # Validate using LookupHelper.is_valid_csv(), if not valid csv
                # then fail this lookup
                app_file_path = os.path.join(directory, filename)
                full_filepath = app.get_filename(app_file_path)
                try:
                    is_valid, rationale = LookupHelper.is_valid_csv(full_filepath)
                    if not is_valid:
                        reporter_output = ("This file is not an approved file"
                                           " type and not formatted as valid"
                                           " csv. Details: {} File: {}"
                                           .format(rationale, app_file_path))
                        reporter.fail(reporter_output)
                except Exception as err:
                    # TODO: tests needed
                    logger.warn("Error validating lookup. File: {}. Error: {}"
                                .format(full_filepath, err))
                    reporter_output = ("Error opening and validating lookup."
                                       " Please investigate/remove this lookup."
                                       " File: {}".format(app_file_path))
                    reporter.fail(reporter_output)
    else:
        reporter_output = ("The `lookups` directory does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "splunk_appinspect")
@splunk_appinspect.cert_version(min="1.1.19")
def check_metadata_white_list(app, reporter):
    """Check that the `metadata/` directory only contains .meta files."""
    allowed_file_types = [".meta"]
    if app.directory_exists("metadata"):
        for directory, filename, ext in app.iterate_files(basedir="metadata"):
            if ext not in allowed_file_types:
                reporter_output = ("File within the `metadata` directory found"
                                   " with an extension other than `.meta`."
                                   " Please remove this file: {}"
                                   ).format(filename)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("The `metadata` directory does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_root_directory_file_white_list(app, reporter):
    """Check that root directory only contains files with the following
    extensions: '.doc', '.docx', '.md', '.pdf', '.rst', '.rtf', '.txt' or the
    following filenames: 'app.manifest', 'CHANGELOG', 'CONTRIBUTORS', 'LICENSE',
    'README'.
    """
    allowed_file_types = [".doc", ".docx", ".md", ".pdf", ".rst", ".rtf", ".txt"]
    allowed_filenames = ["app.manifest", "CHANGELOG", "CONTRIBUTORS", "LICENSE",
        "README"]
    for directory, filename, ext in app.iterate_files(recurse_depth=0):
        if ext not in allowed_file_types and filename not in allowed_filenames:
            reporter_output = ("Please investigate this file: {}"
                               ).format(filename)
            reporter.manual_check(reporter_output, filename)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_static_directory_file_white_list(app, reporter):
    """Check that the `static/` directory contains only known file types."""
    allowed_file_types = [".css", ".csv",
                          ".eot",
                          ".gif",
                          ".htm", ".html",
                          ".ico",
                          ".jpeg", ".jpg",
                          ".kmz",
                          ".less",
                          ".map", ".md",
                          ".otf",
                          ".pdf", ".png",
                          ".rst",
                          ".sass", ".scss", ".svg",
                          ".ttf", ".txt",
                          ".woff", ".woff2",
                          ".xhtml", ".xml"]
    if app.directory_exists("static"):
        for directory, filename, ext in app.iterate_files(basedir="static"):
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(filename)
                reporter.manual_check(reporter_output, filename)
    else:
        reporter_output = ("The `static` directory does not exist.")
        reporter.not_applicable(reporter_output)


# ------------------------------------------------------------------------------
# Grey List Checks Go Here
# ------------------------------------------------------------------------------
# -------------------
# authorize.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_authorize_conf_admin_all_objects_privileges(app, reporter):
    """Check that authorize.conf does not grant excessive administrative
    permissions to the user.
    """
    if app.file_exists("default", "authorize.conf"):
        authorize_conf_file = app.authorize_conf()
        properties_to_validate = ["admin_all_objects",
                                  "change_authentication",
                                  "importRoles"]
        import_roles_to_prevent = {"admin", "sc_admin"}
        for section in authorize_conf_file.sections():
            # Ignore capability stanzas
            if section.name.startswith("capability::"):
                continue
            for property_to_validate in properties_to_validate:
                if not section.has_option(property_to_validate):
                    continue
                value = section.get_option(property_to_validate).value
                if property_to_validate == "importRoles":
                    # Check importRoles for inheriting of blacklisted roles
                    # using set intersection of importRoles & blacklisted roles
                    bad_roles = set(value.split(";")) & import_roles_to_prevent
                    for bad_role in bad_roles:
                        reporter_output = ("authorize.conf [{}] attempts to"
                                           " inherit from the `{}` role."
                                           ).format(section.name, bad_role)
                        reporter.fail(reporter_output)
                elif value == "enabled":
                    reporter_output = ("authorize.conf [{}] contains `{} ="
                                       " enabled`").format(section.name,
                                                           property_to_validate)
                    reporter.fail(reporter_output)
    else:
        reporter_output = ("authorize.conf does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_alert_actions_conf_for_alert_execute_cmd_properties(app, reporter):
    """Check that commands referenced in the `alert.execute.cmd` property of all
    alert actions are checked for compliance with Splunk Cloud security policy.
    """
    if app.file_exists("default", "alert_actions.conf"):
        alert_actions = app.get_alert_actions()
        for alert_action in alert_actions.get_alert_actions():
            if alert_action.alert_execute_cmd_specified():
                reporter_output = ("Alert action [{}] has an alert.execute.cmd"
                                   " specified. Please check this command: `{}`"
                                   ).format(alert_action.name,
                                            alert_action.alert_execute_cmd)
                reporter.manual_check(reporter_output, "default/alert_actions.conf")
    else:
        reporter_output = ("alert_actions.conf does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# indexes.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_indexes_conf_only_uses_splunk_db_variable(app, reporter):
    """Check that indexes defined in `indexes.conf` use relative paths starting
    with $SPLUNK_DB.
    """
    properties_to_validate = ["bloomHomePath",
                              "coldPath",
                              "homePath",
                              "summaryHomePath",
                              "thawedPath", "tstatsHomePath"]
    path_pattern_string = "^\$SPLUNK_DB"
    if app.file_exists("default", "indexes.conf"):
        indexes_conf_file = app.indexes_conf()

        not_using_splunk_db_matches = [(section.name, property_key)
                                       for section
                                       in indexes_conf_file.sections()
                                       for property_key, property_value
                                       in section.items()
                                       if(property_key in properties_to_validate and
                                          re.search(path_pattern_string, property_value) is None)]

        for stanza_name, property_matched in not_using_splunk_db_matches:
            reporter_output = ("The stanza [{}] has the property {}, that is"
                               " using a path that does not contain $SPLUNK_DB."
                               " Please make sure that only $SPLUNK_DB is used."
                               ).format(stanza_name, property_matched)
            reporter.fail(reporter_output)

    else:
        reporter_output = ("indexes.conf does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_index_volume_usage(app, reporter):
    """Check that `indexes.conf` does not declare volumes."""
    path_pattern_string = "^volume:"
    if app.file_exists("default", "indexes.conf"):
        indexes_conf_file = app.indexes_conf()

        volume_stanza_names = [section.name
                               for section
                               in indexes_conf_file.sections()
                               if re.search(path_pattern_string, section.name)]
        for stanza_name in volume_stanza_names:
            reporter_output = ("The stanza [{}] was declared as volume."
                               ).format(stanza_name)
            reporter.fail(reporter_output)

    else:
        reporter_output = ("indexes.conf does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# inputs.conf
# -------------------
@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_appropriate_inputs_monitor_stanza(app, reporter):
    """Check that apps only monitor their own directory
    `$SPLUNK_HOME/etc/apps/<app-dir>/*`.
    """
    if app.file_exists("default", "inputs.conf"):
        expected_monitor_base_value = "$SPLUNK_HOME/etc/apps"

        expected_monitor_value = "{}/{}".format(expected_monitor_base_value,
                                                app.name)

        inputs_configuration_file = app.inputs_conf()

        monitor_stanzas = [stanza_name
                           for stanza_name in inputs_configuration_file.section_names()
                           if re.search("^monitor:\/\/", stanza_name)]
        incorrect_monitor_stanzas = [monitor_stanza
                                     for monitor_stanza in monitor_stanzas
                                     if not monitor_stanza.startswith("monitor://{}".format(expected_monitor_value))]

        for incorrect_monitor_stanza in incorrect_monitor_stanzas:
            reporter_output = ("default/inputs.conf contains a [monitor://]"
                               " stanza that is monitoring more than allowed."
                               " Please remove this functionality."
                               " Stanza: [{}]"
                               " App path: {}"
                               ).format(incorrect_monitor_stanza,
                                        expected_monitor_value)
            reporter.fail(reporter_output)
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")


@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_splunk_var_log_monitoring(app, reporter):
    """Check that apps do not monitor the `$SPLUNK_HOME/var/log/*` directory."""
    if app.file_exists("default", "inputs.conf"):
        expected_monitor_base_value = "$SPLUNK_HOME/var/log"

        inputs_configuration_file = app.inputs_conf()

        monitor_stanzas = [stanza_name
                           for stanza_name in inputs_configuration_file.section_names()
                           if re.search("^monitor:\/\/", stanza_name)]
        incorrect_monitor_stanzas = [monitor_stanza
                                     for monitor_stanza in monitor_stanzas
                                     if monitor_stanza.startswith("monitor://{}".format(expected_monitor_base_value))]

        for incorrect_monitor_stanza in incorrect_monitor_stanzas:
            reporter_output = ("Apps should not monitor $SPLUNK_HOME/var/log/*"
                               " as Splunk already ensures files in this folder"
                               " are are monitored."
                               ).format(incorrect_monitor_stanza)
            reporter.warn(reporter_output)
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_monitor_for_parent_path(app, reporter):
    """Checks that the [monitor] stanza does not use `..` in any part of its
    path.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_configuration_file = app.inputs_conf()

        monitor_stanzas = [stanza_name
                           for stanza_name in inputs_configuration_file.section_names()
                           if stanza_name.startswith("monitor")]

        incorrect_monitor_stanzas = [stanza_name
                                     for stanza_name in monitor_stanzas
                                     if (".." in stanza_name.split("/") or
                                         ".." in stanza_name.split("\\"))]

        for incorrect_monitor_stanza in incorrect_monitor_stanzas:
            reporter_output = ("default/inputs.conf contains a [monitor://]"
                               " stanza that is using relative paths for a"
                               " parent directory. This is not allowed."
                               " Stanza: [{}]").format(incorrect_monitor_stanza)
            reporter.fail(reporter_output)
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")


@splunk_appinspect.tags("cloud", "inputs_conf", "manual")
@splunk_appinspect.cert_version(min="1.2.1")
def check_for_inputs_fifo_usage(app, reporter):
    """Check [fifo] stanza is not used in `inputs.conf`."""
    if app.file_exists("default", "inputs.conf"):
        inputs_configuration_file = app.inputs_conf()

        fifo_stanzas = [stanza_name
                        for stanza_name in inputs_configuration_file.section_names()
                        if re.search("^fifo:\/\/", stanza_name)]

        for fifo_stanza in fifo_stanzas:
            reporter_output = ("default/inputs.conf contains a [fifo://]"
                               " stanza that is not allowed."
                               " Please remove this functionality."
                               " Stanza: [{}]").format(fifo_stanza)
            reporter.manual_check(reporter_output, 'default/inputs.conf')
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")


@splunk_appinspect.tags("splunk_appinspect", "cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_fifo_for_parent_path(app, reporter):
    """Checks that the [fifo] stanza does not use `..` in any part of its
    path.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_configuration_file = app.inputs_conf()
        fifo_stanzas = [stanza_name
                        for stanza_name in inputs_configuration_file.section_names()
                        if stanza_name.startswith("fifo")]

        incorrect_fifo_stanzas = [stanza_name
                                  for stanza_name in fifo_stanzas
                                  if (".." in stanza_name.split("/") or
                                      ".." in stanza_name.split("\\"))]

        for incorrect_fifo_stanza in incorrect_fifo_stanzas:
            reporter_output = ("default/inputs.conf contains a [monitor://]"
                               " stanza that is using relative paths for a"
                               " parent directory. This is not allowed."
                               " Stanza: [{}]").format(incorrect_fifo_stanza)
            reporter.fail(reporter_output)
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_tcp(app, reporter):
    """Check that `default/inputs.conf` does not contain a `tcp` stanza."""
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if section.startswith("tcp://"):
                reporter_output = ("The `default/inputs.conf` specifies `tcp`"
                                   " this is prohibited in Splunk Cloud. An alternative is to"
                                   " use `tcp-ssl`. Stanza [{}]".format(section))
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_splunk_tcp(app, reporter):
    """Check that `default/inputs.conf` does not contain a `splunktcp`
    stanza.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if re.search("^splunktcp(?!-ssl)", section):
                reporter_output = ("The `default/inputs.conf` specifies"
                                   " `splunktcp` this is prohibited in Splunk"
                                   " Cloud. An alternative is to use"
                                   " `splunktcp-ssl`. Stanza: [{}]"
                                   ).format(section)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_fschange(app, reporter):
    """Check that `default/inputs.conf` does not contain a `fschange`
    stanza.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if section.startswith("fschange"):
                reporter_output = ("The `default/inputs.conf` specifies"
                                   " `fschange` this is prohibited in Splunk"
                                   " Cloud. Stanza: [{}]").format(section)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_global_settings(app, reporter):
    """Check that `default/inputs.conf` does not use any global settings."""
    # Global settings should be grouped under the "default" stanza for the
    # ConfigurationFile object that this library uses
    if app.file_exists("default", "inputs.conf"):
        global_stanza_name = "default"
        inputs_conf = app.inputs_conf()
        if inputs_conf.has_section(global_stanza_name):
            for option_name, option_value in inputs_conf.get_section(global_stanza_name).items():
                reporter_output = ("The `default/inputs.conf` specifies"
                                   " global settings. These are prohibited in"
                                   " Splunk Cloud instances. Please remove this"
                                   " functionality."
                                   " Property: {} = {}"
                                   ).format(option_name, option_value)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_http_global_usage(app, reporter):
    """Check that `default/inputs.conf` does not contain a `[http]`
    stanza.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if section == "http":
                reporter_output = ("The `default/inputs.conf` specifies a"
                                   " global `[http]` stanza. This is prohibited"
                                   " in Splunk Cloud instances. Please change"
                                   " this functionality to target local"
                                   " settings by using [http://] instead."
                                   " Stanza: [{}]"
                                   ).format(section)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_splunktcptoken(app, reporter):
    """Check that `default/inputs.conf` does not contain a `splunktcptoken`
    stanza.
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if section.startswith("splunktcptoken"):
                reporter_output = ("The `default/inputs.conf` specifies"
                                   " `splunktcptoken` this is prohibited in"
                                   " Splunk Cloud. Stanza: {}").format(section)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.1")
def check_inputs_conf_for_batch(app, reporter):
    """Check that batch input accesses files in a permitted way.

    To be permissible, the batch input must meet the following criteria:
        1) The file path needs to match a file in the directory "$SPLUNK_HOME/var/spool/splunk/"
        2) The file name needs to be application specific
        3) The file name should not end with "stash" or "stash_new"
    """
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        batch_input_regex_string = r'^batch[:][\/][\/][$]SPLUNK_HOME[/\\]var[/\\]spool[/\\]splunk[/\\][.][.][.]stash(?!_new).+$'
        batch_input_regex = re.compile(batch_input_regex_string)
        for section in inputs_conf.section_names():
            if section.startswith("batch://"):
                match = batch_input_regex.match(section)
                if not match:
                    reporter_output = ("The batch input is prohibited in Splunk Cloud"
                                       " because it is destructive unless used for"
                                       " event spooling using application specific"
                                       " stash files (e.g.,\"batch://$SPLUNK_HOME/"
                                       "var/spool/splunk/...stash_APP_SPECIFIC_WORD\")."
                                       " Stanza: [{}]").format(section)
                    reporter.fail(reporter_output, file_name="default/inputs.conf")
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags("cloud", "splunk_appinspect")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_udp(app, reporter):
    """Check that inputs.conf does not have any UDP inputs."""
    if app.file_exists("default", "inputs.conf"):
        inputs_conf = app.inputs_conf()
        for section in inputs_conf.section_names():
            if section.startswith("udp"):
                reporter_output = ("The `default/inputs.conf` specifies `udp`"
                                   " this is prohibited in Splunk Cloud."
                                   " Stanza: [{}]").format(section)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# setup.xml
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_setup_xml_for_incorrect_password_rest_endpoint(app, reporter):
    """Check that all passwords configured in setup.xml are stored in the
    storage/passwords endpoint. (Documentation)[http://docs.splunk.com/Documentation/Splunk/6.4.2/AdvancedDev/SetupExampleCredentials]
    """
    if app.file_exists("default", "setup.xml"):
        full_filepath = app.get_filename("default", "setup.xml")
        soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
        block_elements_with_passwords = [block_element
                                         for block_element
                                         in soup.find_all("block")
                                         for input_element
                                         in block_element.find_all("input", {"field": "password"})]
        for block_element in block_elements_with_passwords:
            block_title = block_element.get("title", "<Block Title Not Found>")
            if block_element.has_attr("endpoint"):
                endpoint = block_element["endpoint"].lower().strip()
                if endpoint == "storage/passwords":
                    pass  # Success - This block element is pointing to storage/passwords and contains a type element of password
                else:
                    # not storage/passwords, could be a custom endpoint
                    reporter_output = ("Block `{}` contains a password which is"
                                       " stored in the `{}` endpoint. Please"
                                       " use the `storage/passwords` endpoint."
                                       ).format(block_title, endpoint)
                    reporter.manual_check(reporter_output)
            else:
                # No endpoint
                reporter_output = ("No endpoint specified for block `{}`."
                                   ).format(block_title)
                reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/setup.xml` does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# transforms.conf
# -------------------
@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_transforms_conf_for_external_cmd(app, reporter):
    """Check that `transforms.conf` does not contain any transforms with an
    `external_cmd=<string>` attribute.
    """
    if app.file_exists("default", "transforms.conf"):
        transforms_conf = app.transforms_conf()
        external_command_stanzas = [section
                                    for section
                                    in transforms_conf.sections()
                                    if section.has_option("external_cmd")]
        for external_command_stanza in external_command_stanzas:
            reporter_output = ("The `transforms.conf` stanza [{}] is"
                               " using the `external_cmd` property. Please"
                               " investigate."
                               ).format(external_command_stanza.name)
            reporter.manual_check(reporter_output, 'transforms.conf')
    else:
        reporter_output = ("`default/transforms.conf` does not exist.")
        reporter.not_applicable(reporter_output)


# ------------------------------------------------------------------------------
# Blacklist Checks Go Here
# ------------------------------------------------------------------------------
def _blacklist_conf(app, reporter, conf_filename, failure_reason):
    """Helper method to fail for existence of conf file.
    Args:
        app (App): App to check
        reporter (Reporter): Reporter to report FAIL or NA
        conf_filename (str): filename of conf file in default/ including extension
        failure_reason (str): reason for failure to be passed to user if file exists
    """
    if app.file_exists("default", conf_filename):
        reporter_output = ("This file is prohibited. Details: {}."
                           " Please remove this file: default/{}"
                           .format(failure_reason, conf_filename))
        reporter.fail(reporter_output)
    else:
        reporter_output = ("`default/{}` does not exist.".format(conf_filename))
        reporter.not_applicable(reporter_output)


# -------------------
# audit.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_audit_conf_black_list(app, reporter):
    """Check that app does not contain audit.conf, as it is prohibited in
    Splunk Cloud due to its ability to configure/disable cryptographic signing
    and certificates.
    """
    _blacklist_conf(app, reporter, "audit.conf",
        "Splunk Cloud does not permit apps to control whether to perform"
        " cryptographic signing of events in _audit nor which certificates"
        " to use to that end.")


# -------------------
# authentication.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_authentication_conf_black_list(app, reporter):
    """Check that app does not contain authentication.conf, as it is
    prohibited in Splunk Cloud due to its ability to configure LDAP
    authentication and could contain LDAP credentials in plain text.
    """
    _blacklist_conf(app, reporter, "authentication.conf",
        "authentication.conf configures LDAP authentication for logging into"
        " Splunk Cloud and may also contain LDAP credentials neither of which"
        " are permitted.")


# -------------------
# crawl.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "splunk_6_0", "deprecated_feature",
                        "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_crawl_conf_black_list(app, reporter):
    """Check that app does not contain crawl.conf as it was deprecated in Splunk
    6.0 and as it allows Splunk to introspect the filesystem which is not
    permitted in Splunk Cloud.
    """
    # This check is redundant with deprecated features in Splunk 6.0, however
    # Cloud Ops permits deprecated features that aren't harmful, so this check
    # is necessary to prevent usage in Cloud.
    _blacklist_conf(app, reporter, "crawl.conf",
        "crawl.conf allows Splunk to introspect the filesystem which is not "
        "permitted.")


# -------------------
# datatypesbnf.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_datatypesbnf_conf_black_list(app, reporter):
    """Check that app does not contain datatypesbnf.conf, as it is prohibited
    in Splunk Cloud.
    """
    _blacklist_conf(app, reporter, "datatypesbnf.conf",
        "datatypesbnf.conf is not permitted for Splunk Cloud pending further"
        " evaluation.")


# -------------------
# default-mode.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_default_mode_conf_black_list(app, reporter):
    """Check that app does not contain default-mode.conf is as it is
    prohibited in Splunk Cloud due to the fact that Splunk Light Forwarders and
    Splunk Universal Forwarders are not run in Splunk Cloud.
    """
    _blacklist_conf(app, reporter, "default-mode.conf",
        "default-mode.conf describes the alternate setups used by the Splunk"
        " Light Forwarder and Splunk Universal Forwarder which are not run in"
        " Splunk Cloud.")


# -------------------
# deployment.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "splunk_5_0", "removed_feature",
                        "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_deployment_conf_black_list(app, reporter):
    """Check that app does not contain deployment.conf. Apps should leave
    deployment configuration up to Splunk administrators.

    Also, deployment.conf has been removed and replaced by:
      1) deploymentclient.conf - for configuring Deployment Clients
      2) serverclass.conf - for Deployment Server server class configuration.
    """
    _blacklist_conf(app, reporter, "deployment.conf",
        "deployment.conf has been removed and replaced by 1)"
        " deploymentclient.conf - for configuring Deployment Clients and 2)"
        " serverclass.conf - for Deployment Server server class configuration."
        " Note that both deploymentclient.conf and serverclass.conf are"
        " prohibited for Splunk Cloud and App Certification, however.")


# -------------------
# deploymentclient.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_deploymentclient_conf_black_list(app, reporter):
    """Check that app does not contain deploymentclient.conf as it configures
    the deployment server client. Apps should leave deployment configuration up
    to Splunk administrators.
    """
    _blacklist_conf(app, reporter, "deploymentclient.conf",
        "deploymentclient.conf configures the client of the deployment server"
        " which is not permitted.")


# -------------------
# instance.cfg.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_instance_cfg_conf_black_list(app, reporter):
    """Check that app does not contain instance.cfg.conf. Apps should not
    configure server/instance specific settings.
    """
    _blacklist_conf(app, reporter, "instance.cfg.conf",
        "instance.cfg.conf configures server/instance specific settings to set"
        " a GUID per server. Apps should not configure these settings and"
        " leave configuration up to Splunk administrators.")


# -------------------
# literals.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_literals_conf_black_list(app, reporter):
    """Check that app does not contain literals.conf. Apps should not
    alter/override text strings displayed in Splunk Web.
    """
    _blacklist_conf(app, reporter, "literals.conf",
        "literals.conf allows overriding of text, such as search error"
        " strings, displayed in Splunk Web. Apps should not alter these"
        " strings as Splunk users/administrators may rely on them.")


# -------------------
# messages.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_messages_conf_black_list(app, reporter):
    """Check that app does not contain messages.conf. Apps should not
    alter/override messages/externalized strings.
    """
    _blacklist_conf(app, reporter, "messages.conf",
        "messages.conf allows overriding of messages/externalized strings. "
        "Apps should not alter these as Splunk users/administrators may rely "
        "on them.")


# -------------------
# outputs.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_outputs_conf_black_list(app, reporter):
    """Check that app does not contain outputs.conf as forwarding is not
    permitted in Splunk Cloud.
    """
    _blacklist_conf(app, reporter, "outputs.conf",
        "outputs.conf configures forwarding which is not permitted in Splunk"
        " Cloud.")


# -------------------
# pubsub.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_pubsub_conf_black_list(app, reporter):
    """Check that app does not contain pubsub.conf as it defines a custom
    client for the deployment server. Apps should leave deployment
    configuration up to Splunk administrators.
    """
    _blacklist_conf(app, reporter, "pubsub.conf",
        "pubsub.conf defines a custom client for the deployment server, "
        "this is not permitted.")


# -------------------
# segmenters.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_segmenters_conf_black_list(app, reporter):
    """Check that app does not contain segmenters.conf. A misconfigured
    segmenters.conf can result in unsearchable data that could only be
    addressed by re-indexing and segmenters.conf configuration is system-wide.
    """
    _blacklist_conf(app, reporter, "segmenters.conf",
        "segmenters.conf configures how data is indexed and is not permitted "
        "in Splunk Cloud.")


# -------------------
# server.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_server_conf_black_list(app, reporter):
    """Check that app does not contain server.conf is as it is prohibited in
    Splunk Cloud due to its ability to manipulate server settings that are not
    appropriate in Splunk Cloud and can break ingestion.

    [shclustering] settings may be permitted to control replication of files
    in the future.
    """
    _blacklist_conf(app, reporter, "server.conf",
        "server.conf configures Splunk server settings and is not permitted "
        "in Splunk Cloud.")


# -------------------
# serverclass.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_serverclass_conf_black_list(app, reporter):
    """Check that app does not contain serverclass.conf as it defines
    deployment server classes for use with deployment server. Apps should
    leave deployment configuration up to Splunk administrators.
    """
    _blacklist_conf(app, reporter, "serverclass.conf",
        "serverclass.conf configures server classes for use with deployment "
        "server and is not permitted.")


# -------------------
# serverclass.seed.xml.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_serverclass_seed_xml_conf_black_list(app, reporter):
    """Check that app does not contain serverclass.seed.xml.conf as it
    configures deploymentClient to seed a Splunk installation with applications
    at startup time. Apps should leave deployment configuration up to Splunk
    administrators.
    """
    _blacklist_conf(app, reporter, "serverclass.seed.xml.conf",
        "serverclass.seed.xml.conf configures deploymentClient to seed a "
        "Splunk installation with applications at startup time and is not "
        "permitted.")


# -------------------
# source-classifier.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_source_classifier_conf_black_list(app, reporter):
    """Check that app does not contain source-classifier.conf.conf as it
    configures system-wide settings for ignoring terms (such as sensitive
    data).
    """
    _blacklist_conf(app, reporter, "source-classifier.conf",
        "source-classifier.conf configures system-wide terms to ignore when"
        " generating a sourcetype model and is not permitted.")


# -------------------
# sourcetypes.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_sourcetypes_conf_black_list(app, reporter):
    """Check that app does not contain sourcetypes.conf as it is a
    machine-generated file that stores source type learning rules. props.conf
    should be used to define sourcetypes.
    """
    _blacklist_conf(app, reporter, "sourcetypes.conf",
        "sourcetypes.conf stores source type learning rules and is not "
        "permitted.")


# -------------------
# splunk-launch.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_splunk_launch_conf_black_list(app, reporter):
    """Check that app does not contain splunk-launch.conf as it defines
    environment values used at startup time. System-wide environment variables
    should be left up to Splunk administrators.
    """
    _blacklist_conf(app, reporter, "splunk-launch.conf",
        "splunk-launch.conf configures environment values used at startup "
        "time and is not permitted.")


# -------------------
# telemetry.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_telemetry_conf_black_list(app, reporter):
    """Check that app does not contain telemetry.conf as it controls a
    Splunk-internal feature that should not be configured by apps.
    """
    _blacklist_conf(app, reporter, "telemetry.conf",
        "telemetry.conf configures Splunk-internal settings and is not "
        "permitted.")


# -------------------
# user-seed.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_user_seed_conf_black_list(app, reporter):
    """Check that app does not contain user-seed.conf as it is used to
    preconfigure default login and password information.
    """
    _blacklist_conf(app, reporter, "user-seed.conf",
        "user-seed.conf configures default login and password information and "
        "is not permitted.")


# -------------------
# wmi.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.0")
def check_wmi_conf_black_list(app, reporter):
    """Check that app does not contain wmi.conf is as it is prohibited in
    Splunk Cloud due to its ability to configure Splunk to ingest data via
    Windows Management Instrumentation, which should be done via forwarder.
    Forwarders are not permitted in Splunk Cloud.
    """
    _blacklist_conf(app, reporter, "wmi.conf",
        "wmi.conf configures Splunk to ingest data via Windows Management "
        "Instrumentation and is not permitted in Splunk Cloud.")


# ------------------------------------------------------------------------------
# Manual Checks Go Here
# ------------------------------------------------------------------------------
# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_monitoring_of_splunk_cloud_infrastructure(app, reporter):
    """Check that the app does not monitor Splunk Cloud infrastructure."""
    reporter_output = ("Please check for monitoring of Splunk Cloud"
                       " infrastructure.")
    reporter.manual_check(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_lookup_tables_prefilled_with_customer_data(app, reporter):
    """Check for pre-filled lookup tables. Splunk
    Cloud Application Security policy defines "Lookup Table with Customer
    Supplied Data" as a minor risk and may or may not be permitted based on
    cumulative risk score.
    """
    if(app.directory_exists("lookups") and
            os.listdir(app.get_filename("lookups"))):
        reporter_output = ("Please check for Lookup tables pre-filled with customer"
                           " data.")
        reporter.manual_check(reporter_output, 'lookups/')
    else:
        reporter.not_applicable("The lookups/ directory does not exist.")


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_unencrypted_network_communications(app, reporter):
    """Check that all network communications are encrypted."""
    reporter_output = ("Please check for inbound or outbound unencrypted network communications."
                       "All communications with Splunk Cloud must be encrypted.")
    reporter.manual_check(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_udp_network_communications(app, reporter):
    """Check for UDP network communication."""
    reporter_output = ("Please check for inbound or outbound UDP network communications."
                       "Any programmatic UDP network communication is prohibited due to security risks in Splunk Cloud & App Certification."
                       "The use or instruction to configure an app using Settings -> Data Inputs -> UDP within Splunk is permitted. (Note: "
                       "UDP configuration options are not available in Splunk Cloud and as such do not impose a security risk.")
    reporter.manual_check(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_communication_with_third_party_services(app, reporter):
    """Check that the app exports data to 3rd party services. Splunk Cloud
    Application Security policy defines "Exporting Splunk Data to 3rd party
    service" as a moderate security risk and may or may not be permitted based
    on cumulative risk score.
    """
    reporter_output = ("Please check if the app is sending data to third-party"
                       " services.")
    reporter.manual_check(reporter_output)

# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_required_access_to_private_infrastructure(app, reporter):
    """Check that the app requires access to private infrastructure. Splunk
    Cloud Application Security policy defines "Network access required to
    customer service and or infrastructure" as a minor risk and may or may
    not be permitted based on cumulative risk score.
    """
    reporter_output = ("Please check for required access to private"
                       " infrastructure.")
    reporter.manual_check(reporter_output)


@splunk_appinspect.tags("splunk_appinspect", "manual", "cloud")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_binary_files_without_source_code(app, reporter):
    """Check that all executable binary files have matching source code."""
    if platform.system() == "Windows":
        # TODO: tests needed
        reporter.manual_check("Matching source check will be done manually during code review.")
    else:
        # excluding docx, python and egg files to reduce false positives, and covered elsewhere
        exclude_types = [".docx", ".egg", ".py"]

        app_files_iterator = app.iterate_files(excluded_types=exclude_types)
        for directory, file, extension in app_files_iterator:
            current_file_relative_path = os.path.join(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)

            file_output = subprocess.check_output(["file", "-b", current_file_full_path])
            file_output_regex = re.compile("(.)*executable(.)*|(.)*shared object(.)*|(.)*binary(.)*|(.)*archive(.)*",
                                           re.DOTALL | re.IGNORECASE | re.MULTILINE)
            if re.match(file_output_regex, file_output):
                # TODO: tests needed
                reporter_output = ("Please check that any binary files that exist have"
                                   " accompanying source code."
                                   " File: {}  Format: {}").format(current_file_relative_path, file_output)
                reporter.manual_check(reporter_output, current_file_relative_path)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_reverse_shells(app, reporter):
    """Check that the app does not contain reverse shells."""
    reporter_output = ("Please check for reverse shells.")
    reporter.manual_check(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_auto_update_features(app, reporter):
    """Check that the app does not implement auto-update features."""
    bin_directories = [bin_directory
                       for arch in app.arch_bin_dirs
                       for bin_directory in app.arch_bin_dirs[arch]]
    app_has_auto_update_capability = False
    for bin_directory in bin_directories:
        bin_directory_iterator = app.iterate_files(basedir=bin_directory)
        for directory, file, extension in bin_directory_iterator:
            app_has_auto_update_capability = True
            reporter_output = ("Please check the {} directory for app"
                               " auto-update features.").format(directory)
            reporter.manual_check(reporter_output, directory)
            break
    # If an app has nothing in the /bin directory and nothing in any of
    # the architecture-specific directories, it does not have the capacity to
    # update itself.
    if not app_has_auto_update_capability:
        reporter_output = ("No scripts found in /bin or architecture-specific"
                           " directories in app.")
        reporter.not_applicable(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags("splunk_appinspect", "manual")
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_known_vulnerabilities_in_third_party_libraries(app, reporter):
    """Check third party libraries for known vulnerabilities. Splunk Cloud
    Application Security policy defines "Included application libraries have
    multiple vulnerabilities not covered by the components in Transit" as a
    moderate security risk and may or may not be permitted based on
    cumulative risk score.
    """
    reporter_output = ("Please check for known vulnerabilities in third-party"
                       " libraries. Use these links:"
                       " https://web.nvd.nist.gov/view/vuln/search."
                       " and https://nvd.nist.gov/cvss.cfm")
    reporter.manual_check(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.22")
def check_for_perl(app, reporter):
    """Check if the app contains Perl scripts. Perl scripts will be inspected
    for compliance with Splunk Cloud security policy.
    """
    application_files = list(app.iterate_files(types=[".cgi", ".pl", ".pm"]))
    if application_files:
        for directory, file, ext in application_files:
            current_file_relative_path = os.path.join(directory, file)
            reporter_output = ("File: {}").format(current_file_relative_path)
            reporter.manual_check(reporter_output, current_file_relative_path)

    else:
        reporter_output = "No Perl scripts found in app."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.22')
def check_for_javascript(app, reporter):
    """Check if the app contains Javascript files. Javascript scripts will be
    inspected for compliance with Splunk Cloud security policy.
    """
    application_files = list(app.iterate_files(types=[".coffee", ".js", ".js.map"]))
    if application_files:
        for directory, file, ext in application_files:
            current_file_relative_path = os.path.join(directory, file)
            reporter_output = ("Javascript file found."
                               " File: {}").format(current_file_relative_path)
            reporter.manual_check(reporter_output, current_file_relative_path)
    else:
        reporter_output = "No Javascript files found in app."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'manual')
@splunk_appinspect.cert_version(min='1.1.22')
def check_for_java(app, reporter):
    """Check if the app contains java files. Java files will be inspected
    for compliance with Splunk Cloud security policy.
    """
    application_files = list(app.iterate_files(types=[".class", ".jar", ".java"]))
    if application_files:
        for directory, file, ext in application_files:
            current_file_relative_path = os.path.join(directory, file)
            reporter_output = ("java file found."
                               " File: {}").format(current_file_relative_path)
            reporter.manual_check(reporter_output, current_file_relative_path)
    else:
        reporter_output = "No java files found in app."
        reporter.not_applicable(reporter_output)
