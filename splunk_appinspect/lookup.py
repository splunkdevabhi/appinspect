# Copyright 2018 Splunk Inc. All rights reserved.

# Python Standard Libraries
import csv


# From http://docs.splunk.com/Documentation/SplunkCloud/6.6.0/Knowledge/ConfigureCSVlookups:
LOOKUP_HEADER_CHAR_LIMIT = 4096
LOOKUP_EMPTY_MESSAGE = "Lookups should not be empty. Please remove this lookup."
LOOKUP_HEADER_CHAR_LIMIT_MESSAGE = (
    "Lookups headers should contain no more than {} characters. Please"
    " edit/remove this lookup.".format(LOOKUP_HEADER_CHAR_LIMIT)
)
LOOKUP_MAC_LINE_ENDINGS_MESSAGE = (
    "Lookups should not contain pre-OS X (OS 9 or earlier) Macintosh-style"
    " line endings. Please edit/remove this lookup."
)
LOOKUP_COLUMN_MISMATCH_MESSAGE = (
    "The number of columns in row {} ({} columns) does not match the number of"
    " columns in the csv's header ({} columns). The header is considered row"
    " 1. Please edit/remove this lookup."
)
LOOKUP_NON_UTF8_MESSAGE = (
    "Lookups should only contain utf-8 characters. Plain ascii text is"
    " supported, as is any character set that is also valid utf-8. Please"
    " edit/remove this lookup."
)


class LookupHelper(object):
    """Helper class for Splunk lookups.

    Standards for lookups are defined for Splunk Cloud, so using those since no other standards seem to exist:
    http://docs.splunk.com/Documentation/SplunkCloud/6.6.0/Knowledge/ConfigureCSVlookups

    There are a few restrictions to the kinds of CSV files that can be used for CSV lookups:

     - The table represented by the CSV file should have at least two columns. One of those columns should represent a field with a set of values that includes those belonging to a field in your events. The column does not have to have the same name as the event field. Any column can have multiple instances of the same value, as this represents a multivalued field.
     - The CSV file cannot contain non-utf-8 characters. Plain ascii text is supported, as is any character set that is also valid utf-8.
     - The following are unsupported:
       - CSV files with pre-OS X (OS 9 or earlier) Macintosh-style line endings (carriage return ("\r") only)
       - CSV files with header rows that exceed 4096 characters.
    """

    @staticmethod
    def is_valid_csv(full_filepath):
        """Valid whether file is valid csv according to http://docs.splunk.com/Documentation/SplunkCloud/6.6.0/Knowledge/ConfigureCSVlookups
        and additional constaints - should have at least one row and number of
        columns must match for all rows

        Args:
            full_filepath (str): Local system filepath to lookup to be examined

        Returns:
            (bool) is_valid, (str) rationale
        """
        with open(full_filepath, "rb") as csvfile:
            file_contents = csvfile.read().strip()
            if len(file_contents) == 0:
                # empty file
                return False, LOOKUP_EMPTY_MESSAGE
            if "\r" in file_contents and "\r\n" not in file_contents:
                return False, LOOKUP_MAC_LINE_ENDINGS_MESSAGE
            try:
                file_contents.decode("utf8")
            except UnicodeDecodeError:
                return False, LOOKUP_NON_UTF8_MESSAGE
            csvfile.seek(0)  # point back to beginning of file
            lookup_header = csvfile.readline()
            if len(lookup_header) > LOOKUP_HEADER_CHAR_LIMIT:
                return False, LOOKUP_HEADER_CHAR_LIMIT_MESSAGE

            csvfile.seek(0)  # point back to beginning of file
            try:
                dialect = csv.Sniffer().sniff(lookup_header, [',', '\t', ';', ' ', ':'])
            except csv.Error as e:
                if 'Could not determine delimiter' in e.message:
                    dialect = None

            csv_data = list(csv.reader(csvfile, dialect=dialect))
            if len(csv_data) == 0:
                return False, LOOKUP_EMPTY_MESSAGE
            header_columns = len(csv_data[0])
            # If each row of file has same number of columns, call it a valid
            # csv - some level of checking is needed as csv.reader() will
            # process just about anything without issue
            for row in range(1, len(csv_data)):
                row_columns = len(csv_data[row])
                if row_columns != header_columns:
                    return False, LOOKUP_COLUMN_MISMATCH_MESSAGE.format(row + 1,
                                                                        row_columns,
                                                                        header_columns)
        return True, "File is valid."
