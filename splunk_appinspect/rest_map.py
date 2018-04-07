# Copyright 2016 Splunk Inc. All rights reserved.

# Python Standard Libraries
import os
import logging
# Custom Libraries
import file_resource
import rest_map_configuration_file
import splunk_appinspect


logger = logging.getLogger(__name__)


class RestHandler(object):
    """ Represents a rest handler. """

    def __init__(self, name, handler_file_name="", handler_module="", handler_module_file_name="", handler_actions="", hander_type=""):
        self.name = name
        self.handler_file_name = handler_file_name
        self.handler_module = handler_module
        self.handler_module_file_name = handler_module_file_name
        self.handler_actions = handler_actions
        self.handler_type = hander_type

    def handler_file(self):
        """Represents the file for a specific file

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        handlerfile=<unique filename>
        * Script to execute.
        * For bin/myAwesomeAppHandler.py, specify only myAwesomeAppHandler.py.
        """
        return file_resource.FileResource(self.handler_file_name)

    def handler(self):
        """Represents the file for a module in a file file

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        # handler=<SCRIPT>.<CLASSNAME>
        # * The name and class name of the file to execute.
        # * The file *must* live in an application's bin subdirectory.
        # * For example, $SPLUNK_HOME/etc/apps/<APPNAME>/bin/TestHandler.py has a class
        #   called MyHandler (which, in the case of python must be derived from a base
        #   class called 'splunk.rest.BaseRestHandler'). The tag/value pair for this is:
        #   "handler=TestHandler.MyHandler".

        """
        return file_resource.FileResource(self.handler_module_file_name)


class RestMap(object):
    """ Represents a restmap.conf file. """

    def __init__(self, app):
        self.app = app
        self.restmap_conf_file_path = self.app.get_filename('default',
                                                            'restmap.conf')

    def configuration_file_exists(self):
        return self.app.file_exists('default', 'restmap.conf')

    def get_configuration_file(self):
        return self.app.get_config('restmap.conf',
                                   config_file=rest_map_configuration_file.RestMapConfigurationFile())

    def global_handler_file(self):
        """
        The global handler that has a default specifed.

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf
        """
        for section in self.get_configuration_file().section_names():
            if section == "global":
                for key, value in self.get_configuration_file().items(section):
                    if key.lower() == "pythonHandlerPath":
                        file_path = os.path.join(
                            self.app.app_dir, "bin/", value)
                        return file_resource.FileResource(file_path)

        file_path = os.path.join(self.app.app_dir, "bin/", "rest_handler.py")
        return file_resource.FileResource(file_path)

    def handlers(self):
        handler_list = []

        for section in self.get_configuration_file().section_names():

            # Only check sections that are "script" or "admin_external"
            if "script" in section or "admin_external" in section:

                handler = RestHandler(section, self.app.app_dir)

                for key, value in self.get_configuration_file().items(section):

                    # From spec file
                    # script=<path to a script executable>
                    # * For scripttype=python this is optional.  It allows you to run a script
                    #   which is *not* derived from 'splunk.rest.BaseRestHandler'.  This is
                    # rarely used.  Do not use this unless you know what you
                    # are doing.

                    if "script" in section and key.lower() == "script":
                        handler.handler_file_name = os.path.join(
                            self.app.app_dir, "bin/", value)

                    if "script" in section and key.lower() == "handler":
                        handler.handler_file_name = os.path.join(
                            self.app.app_dir, "bin/", value)

                        # TODO: Guard against bad conf (e.g. handler=blah instead of
                        # handler=blah.mod)
                        path = value.split(".")[:1][0] + ".py"

                        handler.handler_module_file_name = os.path.join(
                            self.app.app_dir, "bin/", path)
                        handler.handler_module = value

                    if "admin_external" in section and key.lower() == "handlerfile":
                        handler.handler_file_name = os.path.join(
                            self.app.app_dir, "bin/", value)

                    if "admin_external" in section and key.lower() == "handlertype":
                        handler.handler_type = value

                handler_list.append(handler)

        return handler_list

    def all_admin_patterns(self):
        """
        Gather all endpoint url patterns defined by admin endpoints. Each
        `match=XXXXX` values within [admin:*] stanzas across the conf file
        define the admin prefix, with the "members" defining the individual
        endpoints underneath the admin prefix.

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        patterns = []

        conf_file = self.get_configuration_file()
        for section in conf_file.sections():
            if section.name.startswith("admin:") and section.has_option("match"):
                # Gather the admin root, if match = /my/custom-admin/endpoint
                # then this will expose https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/<each_member>
                admin_root = section.get_option("match").value.strip()
                # Add all members, comma-separated. Each will reside
                # underneath the admin_root defined above, if members = myone,
                # mytwo they will be exposed (using example above) as:
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/myone and
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/mytwo
                if section.has_option("members"):
                    members = section.get_option("members").value.strip().split(",")
                    for member in members:
                        if len(member) == 0:  # skip ""
                            continue
                        member_match = "{}/{}".format(admin_root.strip("/"), member.strip().strip("/"))
                        patterns.append(member_match)

        return patterns

    def all_non_admin_patterns(self):
        """
        Gather all endpoint url patterns that correspond to custom endpoint that
        are NOT defined using the [admin:XXXX] or [admin_external:XXXX] stanzas.
        This will just be a gathering of all `match = ` properties for non-admin
        stanzas across the conf file.

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        patterns = []

        conf_file = self.get_configuration_file()
        admin_prefix = "admin:"
        admin_ext_prefix = "admin_external:"
        for section in conf_file.sections():
            if (not section.name.startswith(admin_prefix) and
                not section.name.startswith(admin_ext_prefix)
                and section.has_option("match")):
                # Grab the value of `match = ` property, add to our url patterns
                # If match = /my/custom/endpoint, then it will be exposed at:
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom/endpoint
                patterns.append(section.get_option("match").value.strip())

        return patterns

    def all_restmap_patterns(self):
        """
        Gather all endpoints defined by restmap.conf

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        return self.all_non_admin_patterns() + self.all_admin_patterns()
