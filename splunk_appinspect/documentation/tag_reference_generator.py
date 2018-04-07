"""This is a module for facilitating auto-generation of documentation required
for releases of Splunk App Inspect.
"""

# Python Standard Libraries
import datetime
import json
import logging
import os
# Third-Party Libraries
import jinja2
import markdown
# Custom Libraries
import splunk_appinspect

logger = logging.getLogger(__name__)


def get_tag_reference_documentation(content_type="text/html"):
    """A function to return the tag descriptions as a consumable Python
    dictionary.

    Used mainly to obscure the fact that it is JSON being parsed.

    Returns:
        dict: A dictionary object that contains the documentation for Splunk
            AppInspect tags
    """
    # This could be done much better
    current_directory = os.path.dirname(os.path.realpath(__file__))
    tag_reference_documentation_path = os.path.join(current_directory, "tag_reference_documentation.json")

    try:
        with open(tag_reference_documentation_path, 'r') as file:
            tag_data = json.load(file)

    except Exception as exception:
        print exception
        logger.error(exception)
        tag_data = {}

    tag_data_to_return = {}

    if content_type == "text/html":
        for key, value in tag_data.iteritems():
            tag_data_to_return[key] = {
                "description": markdown.markdown(value["description"])
            }
    else:
        # Raw string with markdown in line returned
        pass

    return tag_data_to_return


def generate_tag_reference_as_html(custom_checks_dir):
    """Generates an HTML page that lists the criteria required for
    certification. See: http://dev.splunk.com/view/appinspect/SP-CAAAFB2

    Returns:
        String: A string that is the HTML markup of the tag-reference page used
            for Splunk AppInspect releases.
    """
    # TODO: If we decide to add JSON criteria generation, re-work this to rely
    #       on JSON as an input instead, and then pipe that to the template
    current_directory = os.path.dirname(os.path.realpath(__file__))
    template_directory_path = os.path.join(current_directory, "..", "templates")

    template_loader = jinja2.FileSystemLoader(template_directory_path)
    env = jinja2.Environment(loader=template_loader)
    template = env.get_template("tag_reference.html")

    current_date = datetime.datetime.now()
    formatted_current_date = current_date.strftime("%m %B, %Y")

    tags_dictionary = get_tag_reference_documentation()

    rendered_template = template.render(current_date=formatted_current_date,
                                        current_splunk_appinspect_version=splunk_appinspect.version.__version__,
                                        splunk_appinspect_tags=tags_dictionary)

    return rendered_template
