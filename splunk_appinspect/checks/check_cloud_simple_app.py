# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Cloud operations simple application check

This group serves to help validate simple applications in an effort to try and automate the validation process for cloud operations.
"""

# Python Standard Libraries
import logging
import os
import platform
import re
import subprocess
import codecs
# Third-Party Libraries
import bs4
if not platform.system() == "Windows":
    import magic
from lxml import etree
# Custom Libraries
import splunk_appinspect
from splunk_appinspect.documentation import DocumentationLinks
from splunk_appinspect.lookup import LookupHelper
from splunk_appinspect.app_util import find_readmes
from splunk_appinspect.configuration_parser import InvalidSectionError

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# White List Checks Go Here
# ------------------------------------------------------------------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.19")
def check_default_data_ui_views_directory_file_white_list(app, reporter):
    """Check that `default/data/ui/views` contains only allowed files."""
    allowed_file_types = [".html", ".xml"]
    allowed_filenames = ["README"]
    if app.directory_exists("default", "data", "ui", "views"):
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/views"):
            file_path = os.path.join(directory, filename)
            if(ext not in allowed_file_types and
               filename not in allowed_filenames):
                reporter_output = ("File: {}"
                                   " is not allowed in default/data/ui/views."
                                   ).format(file_path)
                reporter.fail(reporter_output, file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
    else:
        reporter_output = ("The `default/data/ui/quickstart` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.5.4")
def check_default_data_ui_manager_for_plain_text_credentials(app, reporter):
    """Check `default/data/ui/manager` for any files that
    use password/key/secret and other keywords.
    """
    if app.directory_exists("default", "data", "ui", "manager"):
        compiled_regex = re.compile("(pass|passwd|password|token|auth|priv|access|secret|login|community|key|privpass)\s*", re.IGNORECASE)
        for directory, filename, ext in app.iterate_files(basedir="default/data/ui/manager"):
            file_path = os.path.join(directory, filename)
            if ext == '.xml':
                full_filepath = app.get_filename(directory, filename)
                soup = bs4.BeautifulSoup(open(full_filepath), "lxml-xml")
                # element has 3 attributes: name, type, label
                # text should be the text string in element
                type_list = soup.find_all("element", {"type": re.compile("^password$")})
                attr_list = soup.find_all("element", {"name": compiled_regex}) + \
                             soup.find_all("element", {"label": compiled_regex})
                if type_list:
                    reporter_output = ("This app uses 'type=password'. Please check"
                                       " whether the app encrypts this password in"
                                       " scripts. File: {}"
                                       ).format(file_path)
                    reporter.manual_check(reporter_output, file_path)
                elif attr_list or _is_text_with_password_(soup, compiled_regex):
                    reporter_output = ("This app uses password/key/secret or other"
                                       " keywords. Please check whether they are"
                                       " secret credentials. If yes, please make"
                                       " sure the app uses 'type=password'"
                                       " attribute and the 'storage/passwords'"
                                       " endpoint to encrypt it. File: {}"
                                       ).format(file_path)
                    reporter.manual_check(reporter_output, file_path)
            else:
                reporter_output = ("This file is in default/data/ui/manager but is not an .xml file."
                                   " Please investigate this file: {}"
                                   ).format(file_path)
                reporter.manual_check(reporter_output, file_path)
    else:
        reporter_output = ("The `default/data/ui/manager` directory does not"
                           " exist.")
        reporter.not_applicable(reporter_output)

def _is_text_with_password_(soup, compiled_regex):
    for element in soup.find_all("element"):
        if element.find(text=compiled_regex):
            return True
    return False

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
                                           " type and is not formatted as valid"
                                           " csv. Details: {} File: {}"
                                           .format(rationale, app_file_path))
                        reporter.fail(reporter_output, app_file_path)
                except Exception as err:
                    # TODO: tests needed
                    logger.warn("Error validating lookup. File: {} Error: {}."
                                .format(full_filepath, err))
                    reporter_output = ("Error opening and validating lookup."
                                       " Please investigate/remove this lookup."
                                       " File: {}".format(app_file_path))
                    reporter.fail(reporter_output, app_file_path)
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
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                reporter_output = ("A file within the `metadata` directory was found"
                                   " with an extension other than `.meta`."
                                   " Please remove this file: {}"
                                   ).format(file_path)
                reporter.fail(reporter_output, file_path)
    else:
        reporter_output = ("The `metadata` directory does not exist.")
        reporter.not_applicable(reporter_output)




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
                          ".xcf", ".xhtml", ".xml"]
    if app.directory_exists("static"):
        for directory, filename, ext in app.iterate_files(basedir="static"):
            file_path = os.path.join(directory, filename)
            if ext not in allowed_file_types:
                # Fail if there exists thumbs.db file
                if filename.lower() == "thumbs.db":
                    reporter_output = ("A prohibited file was found in the `static` directory. File: {}"
                                       .format(file_path))
                    reporter.fail(reporter_output, file_path)
                elif platform.system() == "Windows":
                    reporter_output = ("Please investigate this file manually. File: {}"
                                       ).format(file_path)
                    reporter.manual_check(reporter_output, file_path)
                else:
                    # Inspect the file types by `file` command
                    current_file_relative_path = os.path.join(directory, filename)
                    current_file_full_path = app.get_filename(current_file_relative_path)
                    if current_file_relative_path in app.info_from_file:
                        file_output = app.info_from_file[current_file_relative_path]
                    else:
                        file_output = magic.from_file(current_file_full_path)
                    file_output_regex = re.compile("(.)*ASCII text(.)*|(.)*Unicode(.)*text(.)*",
                                                   re.DOTALL | re.IGNORECASE | re.MULTILINE)
                    # If it is not a text file, then manually check it
                    if not re.match(file_output_regex, file_output):
                        reporter_output = ("This file does not appear to be a text file. Please provide a text file."
                                           "File: {}"
                                           ).format(file_path)
                        reporter.manual_check(reporter_output, file_path)
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
    config_file_paths = app.get_config_file_paths("authorize.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            authorize_conf_file = app.authorize_conf(dir=directory)
            properties_to_validate = ["admin_all_objects",
                                      "change_authentication",
                                      "importRoles"]
            import_roles_to_prevent = {"admin", "sc_admin", "splunk-system-role"}
            for section in authorize_conf_file.sections():
                # Ignore capability stanzas
                if section.name.startswith("capability::"):
                    continue
                for property_to_validate in properties_to_validate:
                    if not section.has_option(property_to_validate):
                        continue
                    option = section.get_option(property_to_validate)
                    lineno = option.lineno
                    value = option.value
                    if property_to_validate == "importRoles":
                        # Check importRoles for inheriting of blacklisted roles
                        # using set intersection of importRoles & blacklisted roles
                        bad_roles = set(value.split(";")) & import_roles_to_prevent
                        for bad_role in bad_roles:
                            reporter_output = ("{} [{}] attempts to"
                                               " inherit from the `{}` role. File: "
                                               "{}, Line: {}."
                                               ).format(file_path,
                                                        section.name,
                                                        bad_role,
                                                        file_path,
                                                        lineno)
                            reporter.fail(reporter_output, file_path, lineno)
                    elif value == "enabled":
                        reporter_output = ("{} [{}] contains `{} ="
                                           " enabled`. File: {}, Line:"
                                           " {}.").format(file_path,
                                                          section.name,
                                                          property_to_validate,
                                                          file_path,
                                                          lineno)
                        reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter_output = ("authorize.conf does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('cloud', 'alert_actions_conf')
@splunk_appinspect.cert_version(min='1.6.1')
def check_alert_actions_exe_exist_for_cloud(app, reporter):
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
                    reporter.warn(mess, filename, lineno)
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
                    continue
                
                reporter_output = ("No executable was found for alert"
                                    " action {}. File: {}, Line: {}."
                                    ).format(alert.name, filename, alert.lineno)
                reporter.warn(reporter_output, filename, alert.lineno)
    else:
        reporter_output = ("No `alert_actions.conf` was detected.")
        reporter.not_applicable(reporter_output)
        

@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_alert_actions_conf_for_alert_execute_cmd_properties(app, reporter):
    """Check that commands referenced in the `alert.execute.cmd` property of all
    alert actions are checked for compliance with Splunk Cloud security policy.
    """
    if app.file_exists("default", "alert_actions.conf"):
        filename = os.path.join('default', 'alert_actions.conf')
        alert_actions = app.get_alert_actions()
        for alert_action in alert_actions.get_alert_actions():
            if alert_action.alert_execute_cmd_specified():
                lineno = alert_action.args['alert.execute.cmd'][1]
                if alert_action.alert_execute_cmd.endswith('.path'):
                    reporter_output = ("Alert action [{}] has an alert.execute.cmd"
                                       " specified with command: `{}`."
                                       " Splunk Cloud prohibits path pointer files because they can be directly"
                                       " used to target executables outside the directory of the app."
                                       " File: {}, Line: {}."
                                       ).format(alert_action.name,
                                                alert_action.alert_execute_cmd,
                                                filename,
                                                lineno)
                    reporter.fail(reporter_output, filename, lineno)
                else:
                    reporter_output = ("Alert action [{}] has an alert.execute.cmd"
                                       " specified. Please check this command: `{}`."
                                       ).format(alert_action.name,
                                                alert_action.alert_execute_cmd)
                    reporter.manual_check(reporter_output)
    else:
        reporter_output = ("alert_actions.conf does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# commands.conf
# -------------------
@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.6.1")
def check_command_scripts_exist_for_cloud(app, reporter):
    """Check that custom search commands have an executable or script per
    stanza.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        file_path = os.path.join("default", "commands.conf")
        for command in custom_commands.get_commands():
            lineno = None
            with_path_suffix_pattern = ".*\.path$"
            if command.file_name_specified():
                lineno = command.args["filename"][1]
                file_name_base, file_name_ext = os.path.splitext(command.file_name)
            # script in bin does not exist or 
            # not match filename in commands.conf
            # (not including .path file here)
            if (command.file_name_specified() and 
                    file_name_ext in custom_commands.ALL_VALID_EXES and 
                        not re.match(with_path_suffix_pattern, command.file_name) and
                            not command.file_name_exe):
                reporter_message = ("No binary file `{}` was found."
                                    " File: {}, Line: {}."
                                    ).format(command.file_name,
                                             file_path,
                                             lineno)
                reporter.warn(reporter_message, file_path, lineno)
            # custom command is v1, only valid for .py and .pl script in default/bin
            elif (not command.is_v2() and 
                    command.count_v1_exes() <= 0):
                reporter_message = ("The stanza [{}] in commands.conf must use a .py or "
                                    ".pl script. File: {}, Line: {}."
                                    ).format(command.name,
                                             file_path,
                                             lineno)
                reporter.warn(reporter_message, file_path, lineno)
            # custom command is v2:
            # - file ends with .path
            elif (command.is_v2() and
                    command.file_name_specified() and
                        re.match(with_path_suffix_pattern, command.file_name)):
                reporter_message = ("The custom command is chunked and "
                                    "the stanza [{}] in commands.conf has field of "
                                    "`filename` with value ends with `.path`. "
                                    "Please manual check whether this path pointer files "
                                    "are inside of app container and use relative path. "
                                    "File: {}, Line: {}."
                                    ).format(command.name,
                                            file_path,
                                            lineno)
                reporter.manual_check(reporter_message, file_path, lineno)
            # custom command is v2:
            # - file per plat in default/bin
            # - file per arch
            elif (command.is_v2() and 
                    ((command.count_win_exes() <= 0 and 
                        command.count_linux_exes() <= 0) and 
                     (command.count_linux_arch_exes() <= 0 and
                        command.count_win_arch_exes() <= 0 and
                            command.count_darwin_arch_exes() <= 0))):
                reporter_message = ("Because the custom command is chunked, "
                                    "the stanza [{}] in commands.conf must use a .py, "
                                    ".pl, .cmd, .bat, .exe, .js, .sh or no extension "
                                    "script. File: {}, Line: {}."
                                    ).format(command.name,
                                            file_path,
                                            lineno)
                reporter.warn(reporter_message, file_path, lineno)
    else:
        reporter.not_applicable("No `commands.conf` file exists.")


# -------------------
# distsearch.conf
# -------------------
@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_distsearch_conf_for_concerning_replicated_file_size(app, reporter):
    """Check if concerningReplicatedFileSize in distsearch.conf is larger 
    than 50 MB.
    """
    path = os.path.join("default", "distsearch.conf")
    if app.file_exists(path):
        distsearch_conf_file = app.distsearch_conf()
        option_exist = distsearch_conf_file.has_option('replicationSettings', 'concerningReplicatedFileSize')
        concerningReplicatedFileSize = distsearch_conf_file.get('replicationSettings', 'concerningReplicatedFileSize') \
                                        if option_exist else 500
        if option_exist and int(concerningReplicatedFileSize) <= 50:
            pass
        else:
            reporter_output = ("The app contains default/distsearch.conf and"
                               " the value of concerningReplicatedFileSize, {} MB, is larger than"
                               " 50 MB. The best practice is files which are >50MB should not"
                               " be pushed to search peers via bundle replication."
                               " By the way, concerningReplicatedFileSize defaults to 500 MB"
                               " so it will be warned in default as long as distsearch.conf exists."
                               ).format(concerningReplicatedFileSize)
            reporter.warn(reporter_output, path)
    else:
        reporter_output = ("distsearch.conf does not exist.")
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

    config_file_paths = app.get_config_file_paths("indexes.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            indexes_conf_file = app.indexes_conf(directory)

            not_using_splunk_db_matches = [(section.name, property_key, property_lineno)
                                           for section
                                           in indexes_conf_file.sections()
                                           for property_key, property_value, property_lineno
                                           in section.items()
                                           if(property_key in properties_to_validate and
                                              re.search(path_pattern_string, property_value) is None)]

            for stanza_name, property_matched, property_lineno in not_using_splunk_db_matches:
                reporter_output = ("The stanza [{}] has the property {} and is"
                                   " using a path that does not contain $SPLUNK_DB."
                                   " Please use a path that contains $SPLUNK_DB."
                                   " File: {}, Line: {}."
                                   ).format(stanza_name,
                                            property_matched,
                                            file_path,
                                            property_lineno)
                reporter.fail(reporter_output, file_path, property_lineno)

    else:
        reporter_output = ("indexes.conf does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.1.20")
def check_for_index_volume_usage(app, reporter):
    """Check that `indexes.conf` does not declare volumes."""
    path_pattern_string = "^volume:"

    config_file_paths = app.get_config_file_paths("indexes.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            indexes_conf_file = app.indexes_conf(directory)

            volume_stanza_names = [(section.name, section.lineno)
                                   for section
                                   in indexes_conf_file.sections()
                                   if re.search(path_pattern_string, section.name)]
            for stanza_name, stanza_lineno in volume_stanza_names:
                reporter_output = ("The stanza [{}] was declared as volume."
                                   "File: {}, Line: {}."
                                   ).format(stanza_name,
                                            file_path,
                                            stanza_lineno)
                reporter.fail(reporter_output, file_path, stanza_lineno)

    else:
        reporter_output = ("indexes.conf does not exist.")
        reporter.not_applicable(reporter_output)


# -------------------
# inputs.conf
# -------------------
@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.6.1")
def check_for_inputs_fifo_or_monitor_usage(app, reporter):
    """Check [fifo] or [monitor] stanza is not used in `inputs.conf`."""
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            expected_monitor_base_value = "$SPLUNK_HOME/var/log/splunk"

            inputs_configuration_file = app.inputs_conf(directory)

            monitor_or_fifo_stanzas = [stanza
                                       for stanza in inputs_configuration_file.sections()
                                       if re.search("^monitor:\/\/", stanza.name) or
                                          re.search("^fifo:\/\/", stanza.name)]


            for stanza in monitor_or_fifo_stanzas:
                additional_message = (" In addition, Splunk has already ensured that files in $SPLUNK_HOME/var/log/splunk"
                                      " are monitored so it doesn't need to configure in the app.")
                reporter_output = ("{}/inputs.conf contains a [monitor://] or [fifo://]"
                                   " stanza that is not allowed in Splunk Cloud."
                                   " Please remove this functionality.{}"
                                   " Stanza: [{}]. File: {}, Line: {}."
                                   ).format(directory,
                                            additional_message if stanza.name.startswith("monitor://{}".format(expected_monitor_base_value)) else "",
                                            stanza.name,
                                            file_path,
                                            stanza.lineno)
                reporter.fail(reporter_output, file_path, stanza.lineno)
    else:
        reporter.not_applicable("The default/inputs.conf does not exist.")



@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_tcp(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not contain a `tcp` stanza."""
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name.startswith("tcp://"):
                    reporter_output = ("The `{}/inputs.conf` specifies `tcp`,"
                                       " which is prohibited in Splunk Cloud. An alternative is to"
                                       " use `tcp-ssl`. Stanza [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_splunk_tcp(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not contain a `splunktcp`
    stanza.
    """
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if re.search("^splunktcp(?!-ssl)", section.name):
                    reporter_output = ("The `{}/inputs.conf` specifies"
                                       " `splunktcp`, which is prohibited in Splunk"
                                       " Cloud. An alternative is to use"
                                       " `splunktcp-ssl`. Stanza: [{}]."
                                       " File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_fschange(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not contain a `fschange`
    stanza.
    """
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name.startswith("fschange"):
                    reporter_output = ("The `{}/inputs.conf` specifies"
                                       " `fschange`, which is prohibited in Splunk"
                                       " Cloud. Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_global_settings(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not use any global settings."""
    # Global settings should be grouped under the "default" stanza for the
    # ConfigurationFile object that this library uses
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            global_stanza_name = "default"
            if inputs_conf.has_section(global_stanza_name):
                for option_name, option_value, option_lineno in inputs_conf.get_section(global_stanza_name).items():
                    reporter_output = ("The `{}/inputs.conf` specifies"
                                       " global settings. These are prohibited in"
                                       " Splunk Cloud instances. Please remove this"
                                       " functionality."
                                       " Property: {} = {}. File: {}, Line: {}."
                                       ).format(directory,
                                                option_name,
                                                option_value,
                                                file_path,
                                                option_lineno)
                    reporter.fail(reporter_output, file_path, option_lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "inputs_conf")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_http_global_usage(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not contain a `[http]`
    stanza.
    """
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name == "http":
                    reporter_output = ("The `{}/inputs.conf` specifies a"
                                       " global `[http]` stanza. This is prohibited"
                                       " in Splunk Cloud instances. Please change"
                                       " this functionality to target local"
                                       " settings by using [http://] instead."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_splunktcptoken(app, reporter):
    """Check that `default/inputs.conf` or `local/inputs.conf` does not contain a `splunktcptoken`
    stanza.
    """
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name.startswith("splunktcptoken"):
                    reporter_output = ("The `{}/inputs.conf` specifies"
                                       " `splunktcptoken`, which is prohibited in"
                                       " Splunk Cloud. Stanza: [{}]."
                                       " File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.5.1")
def check_inputs_conf_for_batch(app, reporter):
    """Check that batch input accesses files in a permitted way.

    To be permissible, the batch input must meet the following criteria:
        1) The file path needs to match a file in the directory "$SPLUNK_HOME/var/spool/splunk/"
        2) The file name needs to be application specific "$SPLUNK_HOME/etc/apps/<my_app>"
        3) The file name should not end with "stash" or "stash_new"
    """
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            batch_input_regex_string = r'^batch[:][\/][\/][$]SPLUNK_HOME[/\\]var[/\\]spool[/\\]splunk[/\\][.][.][.]stash(?!_new).+$'
            batch_input_regex_string_for_app_dir = r'^batch[:][\/][\/][$]SPLUNK_HOME[/\\]etc[/\\]apps[/\\]' + re.escape(app.name) + r'[/\\].*$'
            batch_input_regex = re.compile(batch_input_regex_string)
            batch_input_regex_for_app_dir = re.compile(batch_input_regex_string_for_app_dir)
            for section in inputs_conf.sections():
                if section.name.startswith("batch://"):
                    match = batch_input_regex.match(section.name)
                    match_for_app_dir = batch_input_regex_for_app_dir.match(section.name)
                    if not match and not match_for_app_dir:
                        reporter_output = ("The batch input is prohibited in Splunk Cloud"
                                           " because it is destructive unless used for"
                                           " event spooling using application-specific"
                                           " stash files (e.g.,\"batch://$SPLUNK_HOME/"
                                           "var/spool/splunk/...stash_APP_SPECIFIC_WORD\" or"
                                           " batch://$SPLUNK_HOME/etc/apps/<my_app>)."
                                           " Stanza: [{}]. File: {}, Line: {}."
                                           ).format(section.name,
                                                    file_path,
                                                    section.lineno)
                        reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags("cloud", "splunk_appinspect")
@splunk_appinspect.cert_version(min="1.2.1")
def check_inputs_conf_for_udp(app, reporter):
    """Check that inputs.conf does not have any UDP inputs."""
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name.startswith("udp"):
                    reporter_output = ("The `{}/inputs.conf` specifies `udp`,"
                                       " which is prohibited in Splunk Cloud."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)

@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_inputs_conf_for_ssl(app, reporter):
    """Check that inputs.conf does not have any SSL inputs."""
    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                if section.name == "SSL":
                    reporter_output = ("The `{}/inputs.conf` specifies `SSL`,"
                                       " which is prohibited in Splunk Cloud."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                    reporter.fail(reporter_output, file_path, section.lineno)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.6.1")
def check_scripted_inputs_cmd_path_pattern(app, reporter):
    """Check the cmd path pattern of scripted input defined in inputs.conf"""
    scripted_inputs_cmd_path_pattern = "script://(.*)$"
    absolute_path_pattern = ("\$SPLUNK_HOME/etc/apps/{}/bin/.*").format(app.name)
    relative_path_pattern = "^\.[\\|\\\\|/]bin.*"
    with_path_suffix_pattern = ".*\.path$"

    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                # find cmd path of [script://xxx] stanzas in inputs.conf
                path = re.findall(scripted_inputs_cmd_path_pattern, section.name)
                manual_check_report = ("The `{}/inputs.conf` specifies a `script` input stanza."
                                       " The cmd path of scripted input ends with `.path`."
                                       " Please manual check whether this path pointer files"
                                       " are inside of app container and use relative path."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                warn_report_output = ("The `{}/inputs.conf` specifies a `script` input stanza."
                                       " The best pattern of cmd path of scripted input is"
                                       " $SPLUNK_HOME/etc/apps/AppName/bin/."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                fail_report_output = ("The `{}/inputs.conf` specifies a `script` input stanza."
                                       " This cmd path of scripted input is prohibited in Splunk Cloud."
                                       " Stanza: [{}]. File: {}, Line: {}."
                                       ).format(directory,
                                                section.name,
                                                file_path,
                                                section.lineno)
                if path:
                    path = path[0]
                    if re.match(absolute_path_pattern, path):
                        if re.match(with_path_suffix_pattern, path):
                            reporter.manual_check(manual_check_report, file_path, section.lineno)
                    elif re.match(relative_path_pattern, path):
                        if re.match(with_path_suffix_pattern, path):
                            reporter.manual_check(manual_check_report, file_path, section.lineno)
                        else:
                            reporter.warn(warn_report_output, file_path, section.lineno)
                    else:
                        reporter.fail(fail_report_output, file_path, section.lineno)
                else:
                    reporter_output = ("The scripted input does not exist in inputs.conf.")
                    reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("`inputs.conf` does not exist.")
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags("cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_modular_inputs_scripts_exist_for_cloud(app, reporter):
    """Check that there is a script file in `bin/` for each modular input
    defined in `README/inputs.conf.spec`.
    """
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        
        if modular_inputs.has_modular_inputs():
            file_path = os.path.join("README", "inputs.conf.spec")
            for mi in modular_inputs.get_modular_inputs():
                
                # a) is there a cross plat file (.py) in default/bin?
                if mi.count_cross_plat_exes() > 0:
                    continue

                win_exes = mi.count_win_exes()
                linux_exes = mi.count_linux_exes()
                win_arch_exes = mi.count_win_arch_exes()
                linux_arch_exes = mi.count_linux_arch_exes()
                darwin_arch_exes = mi.count_darwin_arch_exes()

                # b) is there a file per plat in default/bin?
                if(win_exes > 0 or
                        linux_exes > 0):
                    continue

                # c) is there a file per arch?
                if(win_arch_exes > 0 or
                        linux_arch_exes > 0 or
                        darwin_arch_exes > 0):
                    continue
                
                reporter_output = ("No executable exists for the modular "
                                    "input '{}'. File: {}, Line: {}."
                                    ).format(mi.name, file_path, mi.lineno)
                reporter.warn(reporter_output, file_path, mi.lineno)
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


# -------------------
# setup.xml
# -------------------
@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.1.20")
def check_setup_xml_for_incorrect_password_rest_endpoint(app, reporter):
    """Check that all passwords configured in setup.xml are stored in the
    storage/passwords endpoint. (Documentation)[http://docs.splunk.com/Documentation/Splunk/6.4.2/AdvancedDev/SetupExampleCredentials]
    """
    if app.file_exists("default", "setup.xml"):
        file_path = os.path.join("default", "setup.xml")
        full_filepath = app.get_filename("default", "setup.xml")
        try:
            root = etree.parse(full_filepath)
            password_elements = root.xpath("/setup/block/input[type='password']/type")
            endpoint_key = "endpoint"
            endpoint_value = "storage/passwords"
            for password_element in password_elements:
                password_element_lineno = password_element.sourceline
                input_element = password_element.getparent()
                block_element = input_element.getparent()
                block_title = block_element.attrib["title"] \
                    if "title" in block_element.attrib \
                    else "<Block Title Not Found>"
                block_element_lineno = block_element.sourceline

                if endpoint_key not in input_element.attrib and \
                        endpoint_key not in block_element.attrib:
                    reporter_output = ("No endpoint specified for block `{}`."
                                       "File: {}"
                                       ).format(block_title,
                                                file_path,
                                                block_element_lineno)
                    reporter.fail(reporter_output, file_path, block_element_lineno)

                if endpoint_key in input_element.attrib:
                    value = input_element.attrib[endpoint_key]
                    if value == endpoint_value:
                        continue

                if endpoint_key in block_element.attrib:
                    value = block_element.attrib[endpoint_key]
                    if value != endpoint_value:
                        reporter_output = ("Passwords must be stored in the "
                                           "`storage/passwords` endpoint. Block `{}` " 
                                           "contains a password which might not be not stored "
                                           "in the `storage/passwords` endpoint. Please "
                                           "ensure it would be stored in the `storage/passwords` "
                                           "endpoint. File: {}, Line: {}."
                                           ).format(block_title,
                                                    file_path,
                                                    password_element_lineno)
                        reporter.manual_check(reporter_output, file_path, password_element_lineno)
        except etree.XMLSyntaxError:
            reporter_output = ("Invalid XML file: {}").format(file_path)
            reporter.not_applicable(reporter_output)
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
    config_file_paths = app.get_config_file_paths("transforms.conf")
    if config_file_paths:
        for directory, filename in config_file_paths.iteritems():
            file_path = os.path.join(directory, filename)
            transforms_conf = app.transforms_conf(directory)
            external_command_stanzas = [section
                                        for section
                                        in transforms_conf.sections()
                                        if section.has_option("external_cmd")]
            application_files = []
            if external_command_stanzas:
                application_files = list(app.iterate_files(types=[".py"]))
            for external_command_stanza in external_command_stanzas:
                # find `external_cmd` in the sections of transforms.conf
                external_command = external_command_stanza.get_option("external_cmd").value
                external_command_lineno = external_command_stanza.get_option("external_cmd").lineno
                external_command_regex_string = r"^[^\s]+\.py(?=\s)"
                external_command_regex = re.compile(external_command_regex_string)
                script_filename_matches = external_command_regex.search(external_command)
                if script_filename_matches:
                    # if the script type is python
                    script_filename = script_filename_matches.group(0)
                    # find the python file based on the script name
                    script_matches = [file
                                      for file
                                      in application_files
                                      if file[1] == script_filename]
                    if not script_matches:
                        reporter_output = ("`transforms.conf` may not contain any transforms "
                                           " with an `external_cmd=<string>` attribute. "
                                           " The `transforms.conf` stanza [{}] is using the" 
                                           " `external_cmd` property, but the {} file can't be found in the app."
                                           " File: {}, Line: {}."
                                           ).format(external_command_stanza.name,
                                                    script_filename,
                                                    file_path,
                                                    external_command_lineno)
                        reporter.fail(reporter_output, file_path, external_command_lineno)
                else:
                    # manual check other `external_type`, such as executable
                    reporter_output = ("The `transforms.conf` stanza [{}] is"
                                       " using the `external_cmd` property, which is prohibited. "
                                       " Please investigate. Command: {}. File: {}, Line: {}."
                                       ).format(external_command_stanza.name,
                                                external_command,
                                                file_path,
                                                external_command_lineno)
                    reporter.manual_check(reporter_output, file_path, external_command_lineno)
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
        file_path = os.path.join("default", conf_filename)
        reporter_output = ("This file is prohibited. Details: {}."
                           " Please remove this file: {}"
                           .format(failure_reason, file_path))
        reporter.fail(reporter_output, file_path)
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
        " Splunk Cloud and may also contain LDAP credentials, neither of which"
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
        "crawl.conf allows Splunk to introspect the file system, which is not "
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
        " Light Forwarder and Splunk Universal Forwarder, which are not run in"
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
        "deploymentclient.conf configures the client of the deployment server,"
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
        " a GUID per server. Apps leave configuration up to Splunk administrators"
        " and should not configure these settings.")


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
        "outputs.conf configures forwarding, which is not permitted in Splunk"
        " Cloud.")


# -------------------
# passwords.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_that_passwords_conf_not_exist(app, reporter):
    """Check that the app does not have default/passwords.conf, otherwise, warn it.
    """
    path = os.path.join("default", "passwords.conf")
    if app.file_exists(path):
        reporter_output = ("There exists a default/passwords.conf which won't work at the app, please remove it.")
        reporter.warn(reporter_output, path)
    else:
        reporter_output = ("passwords.conf does not exist.")
        reporter.not_applicable(reporter_output)

# -------------------
# props.conf
# -------------------
@splunk_appinspect.tags("splunk_appinspect", "cloud")
@splunk_appinspect.cert_version(min="1.6.1")
def check_that_no_configurations_of_default_source_type_in_props_conf(app, reporter):
    """Check that the app does not contain configurations of default source type in props.conf, 
    which will overwrite the configurations of default source types in system/default/props.conf 
    then it will affect other apps in splunk enterprise/cloud.
    """
    # Now this list is for Splunk 7.2.0, 
    # it needs to be updated while Splunk Version updates
    # Notice: remove [default] stanza here because there exist another check to fail it, 
    # to avoid confusing user appearance of warning and failure at the same time
    list_of_default_source_type = [u'catalina', u'backup_file', 
            u'source::.../var/log/splunk/(web|report)_service(-\\d+)?.log(.\\d+)?', 
            u'breakable_text', u'source::.../splunkd.log(.\\d+)?', 
            u'source::.../token_input_metrics.log(.\\d+)?', u'tcp', 
            u'source::.../var/log/boot.log(.\\d+)?', u'db2_diag', 
            u'source::.../var/log/dmesg(.\\d+)?', u'splunk_directory_monitor', 
            u'cups_access', u'splunkd_stdout', u'preprocess-bzip', 
            u'source::.../var/log/splunk/searches.log', u'web', u'manpage', 
            u'source::.../var/log/splunk/splunkd_stderr.log(.\\d+)?', 
            u'preprocess-Z', u'access_combined', u'_json', u'mysqld_error', 
            u'splunk_python', u'source::.../var/log/anaconda.log(.\\d+)?', 
            u'wmi', u'splunkd_misc', u'splunkd_ui_access', u'apache_error', 
            u'source::.../private/var/log/system.log(.\\d+)?', 
            u'token_input_metrics', u'source::...((.(bak|old))|,v|~|#)', 
            u'osx_crashreporter', u'source::.../(readme|README)...', 
            u'source::.../var/log/splunk/scheduler.log(.\\d+)?', 
            u'source::.../mysql.log(.\\d+)?', 
            u'source::.../var/log/splunk/searchhistory.log(.\\d+)?', 
            u'exim_main', u'source::....bz2?(.\\d+)?', 
            u'source::.../var/log/crashreporter.log(.\\d+)?', u'linux_secure', 
            u'rule::access_combined_wcookie', 
            u'source::.../splunkd_access.log(.\\d+)?', u'psv', 
            u'(?i)source::....zip(.\\d+)?', u'django_access', 
            u'source::.../var/log/splunk/health.log(.\\d+)?', 
            u'fileTrackerCrcLog', u'osx_crash_log', u'source_archive', 
            u'rpmpkgs', u'source::.../var/log/splunk/intentions.log(.\\d+)?', 
            u'wtmp', u'websphere_core', 
            u'source::....(0t|a|ali|asa|au|bmp|cg|cgi|class|d|dat|deb|del|dot|dvi|dylib|elc|eps|exe|ftn|gif|hlp|hqx|hs|icns|ico|inc|iso|jame|jin|jpeg|jpg|kml|la|lhs|lib|lo|lock|mcp|mid|mp3|mpg|msf|nib|o|obj|odt|ogg|ook|opt|os|pal|pbm|pdf|pem|pgm|plo|png|po|pod|pp|ppd|ppm|ppt|prc|ps|psd|psym|pyc|pyd|rast|rb|rde|rdf|rdr|rgb|ro|rpm|rsrc|so|ss|stg|strings|tdt|tif|tiff|tk|uue|vhd|xbm|xlb|xls|xlw)', 
            u'websphere_activity', u'source::WinEventLog...', 
            u'source::....(?i)(evt|evtx)(.\\d+)?', u'snort', 
            u'source::....(cache|class|cxx|dylib|jar|lo|xslt|md5|rpm|deb|iso|vim)', 
            u'access_common', u'log4net_xml', 
            u'source::.../var/log/monthly.out(.\\d+)?', u'clavister', 
            u'preprocess-winevt', u'asterisk_cdr', u'WinNetMonMk', 
            u'rule::exim_main', u'source::WMI...', 
            u'source::.../var/log/splunk/mongod.log(.\\d+)?', 
            u'source::.../var/log/cups/access_log(.\\d+)?', 
            u'source::.../var/log/sa/sar\\d+', u'splunk_resource_usage', 
            u'__singleline', u'syslog', u'ssl_error', u'stash_new', u'anaconda', 
            u'source::.../var/log/splunk/migration.log.*', 
            u'source::.../var/log/httpd/error_log(.\\d+)?', u'ftp', 
            u'asterisk_messages', u'too_small', u'mysql_slow', u'splunk_pdfgen', 
            u'delayedrule::breakable_text', u'linux_messages_syslog', 
            u'cisco:asa', u'source::.../var/log/install.log(.\\d+)?', 
            u'splunk-blocksignature', u'exim_reject', 
            u'source::.../var/log/audit/audit.log(.\\d+)?', 
            u'source::.../private/var/log/windowserver.log(.\\d+)?', 
            u'linux_audit', u'source::...stash', u'splunk_search_history', 
            u'source::.../var/log/splunk/remote_searches.log(.\\d+)?', 
            u'source::.../resource_usage.log(.\\d+)?', 
            u'source::.../var/log/splunk/python.log(.\\d+)?', u'splunkd_access', 
            u'exchange', u'splunkd_crash_log', u'django_service', 
            u'ActiveDirectory', u'procmail', u'linux_bootlog', 
            u'weblogic_stdout', u'mysqld', 
            u'source::.../var/log/splunk/splunkd_stdout.log(.\\d+)?', 
            u'source::.../var/log/httpd/httpd/ssl_error_log(.\\d+)?', 
            u'delayedrule::syslog', u'mcollect_stash', 
            u'http_event_collector_metrics', u'log4php', 
            u'source::.../var/log/weekly.out(.\\d+)?', u'mongod', 
            u'preprocess-gzip', u'WinWinHostMon', u'access_combined_wcookie', 
            u'source::.../syslog(.\\d+)?', u'splunk_disk_objects', 
            u'ignored_type', u'source::.../var/log/splunk/audit.log(.\\d+)?', 
            u'source::.../var/log/asl.log(.\\d+)?', u'generic_single_line', 
            u'source::.../var/log/splunk/pdfgen.log(.\\d+)?', 
            u'source::.../var/log/secure.log(.\\d+)?', 
            u'source::.../var/log/splunk/django_error.log(.\\d+)?', 
            u'source::....(tbz|tbz2)(.\\d+)?', u'source::....tar(.\\d+)?', 
            u'osx_asl', u'anaconda_syslog', 
            u'source::.../(u_|)ex(tend|\\d{4,8})*?.log', 
            u'source::.../var/log/splunk/license_usage(|_summary).log(.\\d+)?', 
            u'source::.../(apache|httpd).../error*', u'fs_notification', 
            u'source::.../var/log/splunk/conf.log(.\\d+)?', u'sendmail_syslog', 
            u'django_error', u'source::.../disk_objects.log(.\\d+)?', 
            u'source::....(css|htm|html|sgml|shtml|template)', 
            u'source::.../procmail(_|.)log', u'statsd', u'osx_monthly', 
            u'splunk_web_service', 
            u'source::.../var/log/splunk/(web|report)_access(-\\d+)?.log(.\\d+)?', 
            u'ruby_on_rails', u'known_binary', 
            u'source::.../var/log/rpmpkgs(.\\d+)?', 
            u'source::.../var/log/anaconda.syslog(.\\d+)?', 
            u'source::.../kvstore.log(.\\d+)?', u'source::....Z(.\\d+)?', 
            u'source::.../http_event_collector_metrics.log(.\\d+)?', 
            u'source::.../var/log/splunk/django_access.log(.\\d+)?', 
            u'source::....crash.log(.\\d+)?', u'iis', u'metrics_csv', 
            u'source::.../var/log/daily.out(.\\d+)?', 
            u'source::.../private/var/log/mail.log(.\\d+)?', u'tsv', 
            u'asterisk_queue', u'source::....csv', u'cisco_syslog', 
            u'source::.../splunkd_ui_access.log(.\\d+)?', 
            u'source::...stash_new', u'rule::access_combined', 
            u'novell_groupwise', 
            u'source::.../var/log/splunk/django_service.log(.\\d+)?', 
            u'source::.../var/log/lastlog(.\\d+)?',  
            u'PerformanceMonitor', u'json_no_timestamp', 
            u'source::.../var/log/spooler(.\\d+)?', u'rule::snort', 
            u'source::.../var/log/secure(.\\d+)?', u'preprocess-tar', 
            u'source::.../var/log/splunk/btool.log(.\\d+)?', u'postfix_syslog', 
            u'lastlog', u'mysqld_bin', u'WinRegistry', u'splunk_help', 
            u'preprocess-targz', u'osx_window_server', u'rule::postfix_syslog', 
            u'splunk_web_access', u'source::.../messages(.\\d+)?', u'sar', 
            u'WinPrintMon', u'kvstore', u'osx_install', u'splunkd_conf', 
            u'cups_error', u'source::.../man/man\\d+/*.\\d+', 
            u'splunk_com_php_error', u'source::....(tar.gz|tgz)(.\\d+)?', 
            u'source::....(jar)(.\\d+)?', u'cisco_cdr', u'csv', u'log4j', 
            u'collectd_http', u'source::.../var/log/wtmp(.\\d+)?', 
            u'splunkd_stderr', u'misc_text', u'websphere_trlog', 
            u'asterisk_event', u'splunkd', u'splunkd_remote_searches', 
            u'source::.../var/log/splunk/*crash-*.log', u'windows_snare_syslog', 
            u'splunk_directory_monitor_misc', 
            u'source::.../var/log/splunk/metrics.log(.\\d+)?', u'searches', 
            u'dmesg', u'source::.../var/log/splunk/splunkd-utility.log(.\\d+)?', 
            u'osx_secure', u'preprocess-zip', u'stash', u'rule::access_common', 
            u'osx_daily', u'source::.../var/log/cups/error_log(.\\d+)?', 
            u'source::.../var/log/ftp.log(.\\d+)?', u'osx_weekly', 
            u'source::....(?<!tar.)gz(.\\d+)?', u'rule::sendmail_syslog', 
            u'spooler', u'source::PerfmonMk...']
    try:
        config_file_paths = app.get_config_file_paths("props.conf")
        if config_file_paths:
            for directory, filename in config_file_paths.iteritems():
                file_path = os.path.join(directory, filename)
                props_config = app.props_conf(directory)
                section_names = props_config.section_names()
                for section_name in section_names:
                    if section_name in list_of_default_source_type:
                        reporter_output = ("In {}, stanza {} has been configured,"
                                           " which will overwrite its default configuration in system/default/props.conf"
                                           " then it will affect other apps in splunk enterprise/cloud."
                                           ).format(file_path, section_name)
                        reporter.warn(reporter_output, file_path)
        else:
            reporter_output = "No props.conf file exists."
            reporter.not_applicable(reporter_output)
    except InvalidSectionError as e:
        reporter_output = "props.conf is malformed. Details: {}".format(e.message)
        reporter.fail(reporter_output)
    except Exception:
        raise

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
        "serverclass.conf configures server classes for use with a deployment "
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
        "Splunk installation with applications at startup time, which is not "
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
        " generating a sourcetype model, which is not permitted.")


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
        "sourcetypes.conf stores source type learning rules, which is not "
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
        "time, which is not permitted.")


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
        "telemetry.conf configures Splunk-internal settings, which is not "
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
        "user-seed.conf configures default login and password information, which "
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
        "Instrumentation, which is not permitted in Splunk Cloud.")


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
        reporter_output = ("Please check for lookup tables pre-filled with"
                           " customer data. Pre-filling lookup tables might"
                           " not be permitted based on the app's cumulative"
                           " risk score. File: lookups/")
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
                       "Any programmatic UDP network communication is prohibited due to security risks in Splunk Cloud and App Certification."
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
    reporter_output = ("Please check whether the app is sending data to third-"
                       " party services, which is not recommended.")
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
        source_types = ['.cpp', '.c', '.java', '.h']
        source_name_pool = {}
        app_files_iterator = app.iterate_files(types = source_types)
        for directory, file, extension in app_files_iterator:
            current_file_relative_path = os.path.join(directory, file)
            source_name_without_extension = os.path.basename(current_file_relative_path).split('.')[0]
            source_name_pool[source_name_without_extension] = current_file_relative_path

        # excluding docx, python and egg files to reduce false positives, and covered elsewhere
        exclude_types = [".docx", ".egg", ".py"]

        readme_names = find_readmes(app)
        readmes_dict = {}
        for readme_name in readme_names:
            full_file_path = os.path.join(app.app_dir, readme_name)
            with codecs.open(full_file_path, encoding='utf-8', errors='ignore') as file:
                readmes_dict[readme_name] = file.read().lower()
        app_files_iterator = app.iterate_files(excluded_types=exclude_types)
        file_output_regex = re.compile("^((?!ASCII text executable)(?!Unicode text executable)(?!Perl script text executable).)*executable(.)*" +
                                        "|(.)*shared object(.)*" +
                                        "|(.)*binary(.)*" +
                                        "|^((?!Zip archive data).)*archive(.)*",
                                       re.DOTALL | re.IGNORECASE | re.MULTILINE)

        for directory, file, extension in app_files_iterator:
            current_file_relative_path = os.path.join(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)

            try:
                # file_output = subprocess.check_output(["file", "-b", current_file_full_path])
                # using magic library to substitute the original file cmd
                if current_file_relative_path in app.info_from_file:
                    file_output = app.info_from_file[current_file_relative_path]
                else:
                    file_output = magic.from_file(current_file_full_path)
            except Exception, e:
                # in case of any further exception, throw a manual check instead of an internal error
                reporter.manual_check("Please manually check {} ({} {} {})\r\n"
                                      "Note if you are using macOS, you might need to \"brew install libmagic\". "
                                      "File: {}"
                                      .format(current_file_relative_path,
                                              e.returncode,
                                              e.cmd,
                                              e.output,
                                              current_file_relative_path),
                                      current_file_relative_path)
            else:
                if re.match(file_output_regex, file_output):
                    binary_name = os.path.basename(current_file_relative_path).split('.')[0]
                    if binary_name in source_name_pool:
                        reporter_output = ("Please ensure the binary files are safe. Source file: "
                                        " Bianry file: {}  Format: {}  Source file: {}").format(current_file_relative_path, file_output, source_name_pool[binary_name])
                        reporter.manual_check(reporter_output, current_file_relative_path)
                    elif len(readme_names) != 0:
                        readme_find = False
                        for readme_name, readme_content in readmes_dict.iteritems():
                            if binary_name in readme_content or "# binary file declaration" in readme_content:
                                reporter_output = ("Please ensure the binary files are safe. Related info might be included in App README."
                                        " Binary file: {}  Format: {}  README: {}").format(current_file_relative_path, file_output, readme_name)
                                reporter.manual_check(reporter_output, current_file_relative_path)
                                readme_find = True
                                break
                        if not readme_find:
                            reporter_output = ("File: {}"
                                " is a binary file (Format: {}) but fail to find any source file nor reference info."
                                " Please attach source code of this binary in the package,"
                                ' OR include any information of those binaries under "# Binary File Declaration" section'
                                " (You might need create one) in your App's REAMDE."
                                " We will manually review the source code of the binary.").format(current_file_relative_path, file_output)
                            reporter.fail(reporter_output)
                    else:
                        reporter_output = ("File: {}"
                            " is a binary file (Format: {}) but fail to find any source file nor reference info."
                            " Please attach source code of this binary in the package,"
                            " OR create an App's README under root directory"
                            ' and include any information of those binaries under "# Binary File Declaration" section'
                            " (You might need create one) in README."
                            " We will manually review the source code of the binary.").format(current_file_relative_path, file_output)
                        reporter.fail(reporter_output)

@splunk_appinspect.tags("cloud", "manual")
@splunk_appinspect.cert_version(min="1.6.1")
def check_that_app_contains_any_windows_specific_components(app, reporter):
    """Check that the app contains MS Windows specific components, which will not 
    function correctly in Splunk Cloud whose OS should be Linux x64.
    """
    if platform.system() == "Windows":
        # TODO: tests needed
        reporter.manual_check("Matching source check will be done manually during code review.")
    else:
        ms_windows_info = ["DOS batch file", "MS Windows", "CRLF line terminators"]
        ms_windows_file_types_in_crlf = ['.ps1', '.psm1']
        excluded_types = ['.ico']
        # only consider default directory here because local directory will be failed
        inputs_conf_path = os.path.join("default", "inputs.conf")
        for path, info in app.info_from_file.iteritems():
            # check if inputs.conf exists
            base, ext = os.path.splitext(path) 
            if inputs_conf_path == path:
                inputs_configuration_file = app.inputs_conf()

                banned_stanzas = [stanza
                                  for stanza in inputs_configuration_file.sections()
                                  if re.search("^monitor:\/\/([a-zA-Z]\:|\.)\\\\", stanza.name) or
                                     re.search("^script:\/\/([a-zA-Z]\:|\.)\\\\", stanza.name) or
                                     re.search("^perfmon:\/\/", stanza.name) or
                                     re.search("^MonitorNoHandle:\/\/", stanza.name) or
                                     re.search("^WinEventLog:\/\/", stanza.name) or
                                     re.search("^admon:\/\/", stanza.name) or
                                     re.search("^WinRegMon:\/\/", stanza.name) or
                                     re.search("^WinHostMon:\/\/", stanza.name) or
                                     re.search("^WinPrintMon:\/\/", stanza.name) or
                                     re.search("^WinNetMon:\/\/", stanza.name) or
                                     re.search("^powershell2:\/\/", stanza.name) or
                                     re.search("^powershell:\/\/", stanza.name)]


                for stanza in banned_stanzas:
                    reporter_output = ("default/inputs.conf contains a stanza for Windows inputs"
                                    " that will not work correctly in Splunk Cloud. (http://docs.splunk.com/Documentation/Splunk/7.1.3/Admin/Inputsconf)"
                                    " Stanza: [{}]. File: {}, Line: {}."
                                    ).format(stanza.name,
                                             path,
                                             stanza.lineno)
                    reporter.warn(reporter_output, path, stanza.lineno)
            else:
                for sub_info in ms_windows_info:
                    if sub_info in info:
                        if ext in excluded_types or \
                           (sub_info == "CRLF line terminators" and ext not in ms_windows_file_types_in_crlf):
                            continue
                        reporter_output = ("The app works for MS Windows platform because {} exists,"
                                           " which is {}. It is only valid at MS Windows platform."
                                           " File: {}".format(path, info, path))
                        reporter.warn(reporter_output, path)
                        break


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
                               " auto-update features, which is prohibited.").format(directory)
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
def check_for_java(app, reporter):
    """Check whether the app contains java files. Java files will be inspected
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

@splunk_appinspect.tags('cloud')
@splunk_appinspect.cert_version(min='1.6.1')
def check_for_implementing_tscollect(app, reporter):
    """Check that use of
    ['tscollect'](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tscollect)
    then fail it.
    """
    # fail all appearance of 'tscollect'
    # if we don't use this command, it shouldn't appear in the app
    # make exception for readme
    matches = app.search_for_pattern('tscollect',excluded_bases=['readme'],excluded_types=['.txt','.md','.me','.1st',''])
    if matches:
        for match in matches:
            file,line = match[0].split(':')
            # make exception for splunk add-on builder
            if file == os.path.join('appserver', 'static', 'js', 'build', 'common.js'):
                pass
            else:
                reporter_output = ("Find `tscollect` which is not allowed in Splunk Cloud"
                                   " because it can eat up disk space with usage of `tscollect`."
                                   " Please don't use `tscollect` in Splunk Cloud."
                                   " File: {}, Line: {}").format(file,line)
                reporter.fail(reporter_output, file, line)
    else:
        reporter.not_applicable("No use of 'tscollect' found.")