# Copyright 2018 Splunk Inc. All rights reserved.

"""
### Modular inputs structure and standards

Modular inputs are configured in an **inputs.conf.spec** file located in the **/README** directory of the app. For more, see <a href="http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsIntro" target="_blank">Modular inputs overview</a>, <a href="http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsSpec" target="_blank">Modular inputs configuration</a>, and <a href="http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsBasicExample#Basic_implementation_requirements" target="_blank">Modular inputs basic example</a>.
"""

# Python Standard Library
import logging
import os
# Custom Modules
import splunk_appinspect


report_display_order = 12

logger = logging.getLogger(__name__)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
@splunk_appinspect.display(report_display_order=1)
def check_inputs_conf(app, reporter):
    """Check that a valid `inputs.conf.spec` file are located in the `README/`
    directory.
    """
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        pass
    else:
        reporter_output = ("No `{}` file exists. Please check that a valid" 
        " `inputs.conf.spec` file is located in the `README/`directory.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
@splunk_appinspect.display(report_display_order=2)
def check_inputs_conf_spec_has_stanzas(app, reporter):
    """Check that README/inputs.conf.spec contains stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        file_path = os.path.join(modular_inputs.specification_directory_path,
                                 modular_inputs.specification_filename)

        inputs_specification_file = modular_inputs.get_specification_file()
        inputs_specification_file_stanzas_count = len(list(inputs_specification_file.sections()))
        if inputs_specification_file_stanzas_count == 0:
            reporter_output = ("The inputs.conf.spec {} does not specify any "
                               "stanzas. File: {}"
                               ).format(modular_inputs.get_specification_app_filepath,
                                        file_path)
            reporter.fail(reporter_output, file_path)
        else:
            pass  # Success - stanzas were found
    else:
        reporter_output = ("No `{}` file exists.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_stanzas_have_properties(app, reporter):
    """Check that modular inputs specify arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        if modular_inputs.has_modular_inputs():
            file_path = os.path.join(modular_inputs.specification_directory_path,
                                     modular_inputs.specification_filename)
            for modular_input in modular_inputs.get_modular_inputs():
                if not modular_input.args_exist():
                    lineno = modular_input.lineno
                    reporter_output = ("The stanza [{}] does not include any args. "
                                       "File: {}, Line: {}."
                                       ).format(modular_input.name,
                                                file_path,
                                                lineno)
                    reporter.fail(reporter_output, file_path, lineno)
                else:
                    pass  # SUCCESS - The modular input has arguments
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("No `{}` file exists.").format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_has_no_duplicate_stanzas(app, reporter):
    """Check that modular inputs do not have duplicate stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()
        file_path = os.path.join(modular_inputs.specification_directory_path,
                                 modular_inputs.specification_filename)

        for error, line_number, section, in inputs_specification_file.errors:
            if error.startswith("Duplicate stanza"):
                reporter_output = ("{}"
                                   " File: {}"
                                   " Stanza: {}"
                                   " Line: {}").format(error,
                                                       file_path,
                                                       section,
                                                       line_number)
                reporter.warn(reporter_output, file_path, line_number)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_has_no_duplicate_properties(app, reporter):
    """Check that modular input stanzas do not contain duplicate arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()
        file_path = os.path.join(modular_inputs.specification_directory_path,
                                 modular_inputs.specification_filename)

        for error, line_number, section, in inputs_specification_file.errors:
            if error.startswith("Repeat item name"):
                reporter_output = ("{}"
                                   " File: {}"
                                   " Stanza: {}"
                                   " Line: {}").format(error,
                                                       file_path,
                                                       section,
                                                       line_number)
                reporter.warn(reporter_output, file_path, line_number)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_inputs_conf_spec_stanza_args_broken_correctly(app, reporter):
    """Check lines breaks are included in configuration when using a modular
    input.
    """

    modular_inputs = app.get_modular_inputs()

    if modular_inputs.has_specification_file():
        raw_specification_file = modular_inputs.get_raw_specification_file()
        file_path = os.path.join(modular_inputs.specification_directory_path,
                                 modular_inputs.specification_filename)

        # From https://github.com/splunk/splunk-app-validator
        if len(raw_specification_file.split('\n')) > 1:
            pass
        else:
            reporter_output = "The inputs.conf.spec has incorrect line breaks. " \
                              "File: {}".format(file_path)
            reporter.fail(reporter_output, file_path)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'modular_inputs')
@splunk_appinspect.cert_version(min='1.1.0')
def check_modular_inputs_scripts_exist(app, reporter):
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
                else:
                    reporter_output = ("No executable exists for the modular "
                                       "input '{}'. File: {}, Line: {}."
                                       ).format(mi.name, file_path, mi.lineno)
                    reporter.fail(reporter_output, file_path, mi.lineno)
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = ("No `{}` was detected."
                           ).format(modular_inputs.specification_filename)
        reporter.not_applicable(reporter_output)
