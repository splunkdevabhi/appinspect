# Copyright 2016 Splunk Inc. All rights reserved.

"""
###  REST endpoints and handler standards

REST endpoints are defined via a [restmap.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Restmapconf)
     file located at `default/restmap.conf`
"""

# Python Standard Library
import logging
# Custom Modules
import splunk_appinspect

logger = logging.getLogger(__name__)

report_display_order = 23


@splunk_appinspect.tags('splunk_appinspect', 'restmap_config', 'cloud')
@splunk_appinspect.cert_version(min='1.1.0')
@splunk_appinspect.display(report_display_order=1)
def check_restmap_conf_exists(app, reporter):
    """Check that `restmap.conf` file exists at `default/restmap.conf` when 
    using REST endpoints.
    """
    rest_map = app.get_rest_map()
    if rest_map.configuration_file_exists():
        pass
    else:
        reporter_output = "No restmap.conf file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags('splunk_appinspect', 'restmap_config')
@splunk_appinspect.cert_version(min='1.1.0')
def check_rest_handler_scripts_exist(app, reporter):
    """Check that each stanza in restmap.conf has a matching handler script."""
    rest_map = app.get_rest_map()
    if rest_map.configuration_file_exists():
        # From ACD-300, ACD-271,ACD-367
        # A rest config can have both, handler and handler_file. Or use the global handler
        # See
        # http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        global_handler = rest_map.global_handler_file()

        if global_handler.exists():
            message = "A global rest handler was found at {}".format(
                global_handler.file_path)
            logger.info(message)

        else:
            logger.info("A global rest handler was not found at {}".format(
                global_handler.file_path))

            handler_list = rest_map.handlers()
            for handler in handler_list:
                if handler.handler_file().exists() or handler.handler().exists():
                    pass
                else:
                    reporter_output = ("Neither the handler or handlerfile specified in the stanza {}"
                                       " was found in app/bin for {} or {}. "
                                       ).format(
                        handler.name,
                        handler.handler_file().file_path,
                        handler.handler().file_path
                    )
                    reporter.fail(reporter_output)
    else:
        pass
