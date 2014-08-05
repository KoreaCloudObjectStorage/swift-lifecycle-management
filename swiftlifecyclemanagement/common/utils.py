import calendar
from datetime import datetime


def gmt_to_timestamp(gmt_time):
    # convert object's last_modified(UTC TIME) to Unix Timestamp
    timestamp = datetime.strptime(gmt_time,
                                  '%a, %d %b %Y %H:%M:%S GMT')
    timestamp = calendar.timegm(timestamp.utctimetuple())
    return timestamp