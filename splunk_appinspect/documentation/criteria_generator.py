"""This is a module for facilitating auto-generation of documentation required
for releases of Splunk App Inspect
"""

# Python Standard Libraries
import datetime
import os
# Third-Party Libraries
import jinja2
# Custom Libraries
import splunk_appinspect


def generate_critera_as_html(included_tags=None, excluded_tags=None, custom_checks_dir=None):
    """Generates an HTML page that lists the criteria required for
    certification. See: http://dev.splunk.com/view/app-cert/SP-CAAAE3H

    Returns:
        String: A string that is the HTML markup that is the criteria page used
            for Splunk AppInspect releases.
    """
    if included_tags is None:
        included_tags = []
    if excluded_tags is None:
        excluded_tags = []

    # TODO: If we decide to add JSON criteria generation, re-work this to rely
    #       on JSON as an input instead, and then pipe that to the template
    current_directory = os.path.dirname(os.path.realpath(__file__))
    template_directory_path = os.path.join(current_directory, "..", "templates")

    standard_groups_iterator = splunk_appinspect.checks.groups()
    custom_groups_iterator = splunk_appinspect.checks.groups(custom_checks_dir=custom_checks_dir)

    template_loader = jinja2.FileSystemLoader(template_directory_path)
    env = jinja2.Environment(loader=template_loader)
    template = env.get_template("html_criteria.html")

    current_date = datetime.datetime.now()
    formatted_current_date = current_date.strftime("%d %B, %Y")
    use_all_tags = (not included_tags and not excluded_tags)

    # defaults to inclusion of ALL tag if not specified
    # otherwise shows only the tags specified
    tags_to_show = []
    if not use_all_tags:
        for included_tag in included_tags:
            tags_to_show.append(included_tag)
    else:
        for group in standard_groups_iterator:
            tags_to_show = tags_to_show + group.tags()
        for group in custom_groups_iterator:
            tags_to_show = tags_to_show + group.tags()

    # Whether or not all tags are used, excluded_tags will remove
    # specified tags in order
    for excluded_tag in excluded_tags:
        tags_to_show.remove(excluded_tag)

    tags_to_show.sort()
    tags_to_show = set(tags_to_show)

    # We really only want splunk_appinspect and cloud to show up as columns
    # to be checked, yeah I'm just hard coding these because they are "special"
    splunk_appinspect_certification_areas = ["splunk_appinspect", "cloud"]

    rendered_criteria_html_markup = template.render(current_date=formatted_current_date,
                                                    current_splunk_appinspect_version=splunk_appinspect.version.__version__,
                                                    splunk_appinspect_certification_areas=splunk_appinspect_certification_areas,
                                                    splunk_appinspect_core_groups=standard_groups_iterator,
                                                    splunk_appinspect_custom_groups=custom_groups_iterator)

    return rendered_criteria_html_markup
