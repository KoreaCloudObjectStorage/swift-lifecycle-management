import calendar
from datetime import datetime


def gmt_to_timestamp(gmt_time):
    # convert object's last_modified(UTC TIME) to Unix Timestamp
    last_modified = datetime.strptime(gmt_time,
                                      '%a, %d %b %Y %H:%M:%S GMT')
    last_modified = calendar.timegm(last_modified.utctimetuple())
    return last_modified