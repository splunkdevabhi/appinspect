
class CronExpression(object):
    """Represents a cron expression"""

    def __init__(self, cron_expression):
        self.expression = cron_expression
        self._is_valid = True
        self.fields = self.expression.split()
        if len(self.fields) != 5:
            self._is_valid = False

    def is_valid(self):
        return self._is_valid

    def is_high_occurring(self):
        try:
            minutes_field = self.fields[0]
            occurrences = CronExpression._get_occurrences_in_an_hour(minutes_field)
            # anything more frequent than "every 5 minutes" is considered as high occurring
            return occurrences.count(True) > (60 / 5)
        except:
            self._is_valid = False
            raise

    @staticmethod
    def _get_occurrences_in_an_hour(minutes_field):
        minute_values = minutes_field.split(',')
        occurrences = [False] * 60
        for value in minute_values:
            CronExpression._fill_occurrence_for_minute_value(occurrences, value)
        return occurrences

    @staticmethod
    def _fill_occurrence_for_minute_value(occurrences, value):
        if CronExpression._is_wildcard_value(value):
            for i in xrange(0, 60):
                occurrences[i] = True
        elif CronExpression._is_step_and_range_value(value):
            step = int(value.split('/')[1])
            ranges = value.split('/')[0].split('-')
            start = int(ranges[0])
            end = int(ranges[1])
            for i in xrange(start, end + 1, step):
                occurrences[i] = True
        elif CronExpression._is_step_value(value):
            step = int(value.split('/')[1])
            for i in xrange(0, 60, step):
                occurrences[i] = True
        elif CronExpression._is_range_value(value):
            ranges = value.split('-')
            start = int(ranges[0])
            end = int(ranges[1])
            for i in xrange(start, end + 1):
                occurrences[i] = True
        elif CronExpression._is_number_value(value):
            occurrences[int(value)] = True
        else:
            raise ValueError('Minute field {} in cron expression is invalid'.format(value))

    @staticmethod
    def _is_wildcard_value(value):
        return '*' == value

    @staticmethod
    def _is_step_value(value):
        return '/' in value

    @staticmethod
    def _is_range_value(value):
        return '-' in value

    @staticmethod
    def _is_step_and_range_value(value):
        return CronExpression._is_step_value(value) and CronExpression._is_range_value(value)

    @staticmethod
    def _is_number_value(value):
        return value.isdigit()
