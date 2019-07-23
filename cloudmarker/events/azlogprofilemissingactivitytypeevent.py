"""Microsoft Azure Log Profile Missing Activity Type Event.

This module defines the :class:`AzLogProfileMissingActivityTypeEvent` class
that identifies if a log profile which is not enable for all the activity
types i.e. Write, Delete and Action. This plugin works on the log profile
properties found in the ``raw`` bucket of ``log_profile`` records.
"""


import logging

from cloudmarker import util

_log = logging.getLogger(__name__)


class AzLogProfileMissingActivityTypeEvent:
    """Azure log profile missing activity type event plugin."""

    def __init__(self):
        """Create an instance of the class.

        Create and instance of the
        :class:`AzLogProfileMissingActivityTypeEvent`.
        """

    def eval(self, record):
        """Evaluate Azure log profiles for enabled activities.

        Arguments:
            record (dict): An Azure log profile record.

        Yields:
            dict: An event record representing an Azure log profile
            which is not enabled for all activity types.

        """
        com = record.get('com', {})
        if com is None:

            return
        if com.get('cloud_type') != 'azure':
            return

        if com.get('record_type') != 'log_profile':
            return

        ext = record.get('ext', {})
        if ext is None:
            return

        raw = record.get('raw', {})
        if raw is None:
            return
        yield from _evaluate_log_profile_for_activities(com, ext, raw)

    def done(self):
        """Perform cleanup work.

        Currently, this method does nothing. This may change in future.
        """


def _evaluate_log_profile_for_activities(com, ext, raw):
    """Evaluate log profile for missing activity type.

    Arguments:
        com (dict): Log profile record `com` bucket
        ext (dict): Log profile record `ext` bucket
        raw (dict): Log profile record `raw` bucket
    Yields:
        dict: An event record representing a log profile which is not enabled
              for an activity.

    """
    _log.info(raw.get('categories'))
    activities = ('Write', 'Delete', 'Action')
    for activity in activities:
        if activity not in raw.get('categories'):
            yield _get_log_profile_activity_event(com, ext, activity)


def _get_log_profile_activity_event(com, ext, missing_activity):
    """Generate log profile missing activity type event.

    Arguments:
        com (dict): Log profile record `com` bucket
        ext (dict): Log profile record `ext` bucket
        missing_activity (string): Missing activity type
    Returns:
        dict: An event record representing SQL DB with disabled TDE

    """
    friendly_cloud_type = util.friendly_string(com.get('cloud_type'))
    reference = com.get('reference')
    description = (
        '{} log profile {} has is not enabled for {} activity.'
        .format(friendly_cloud_type, reference, missing_activity)
    )
    recommendation = (
        'Check {} log profile {} and enable for {} activity.'
        .format(friendly_cloud_type, reference, missing_activity)
    )
    event_record = {
        # Preserve the extended properties from the log profile
        # record because they provide useful context to locate
        # the log profile that led to the event.
        'ext': util.merge_dicts(ext, {
            'record_type': 'log_profile_missing_activity_type_event'
        }),
        'com': {
            'cloud_type': com.get('cloud_type'),
            'record_type': 'log_profile_missing_activity_type_event',
            'reference': reference,
            'description': description,
            'recommendation': recommendation,
        }
    }
    _log.info('Generating log_profile_missing_activity_type_event; %r',
              event_record)
    return event_record
