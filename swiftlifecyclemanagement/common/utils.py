import calendar
from datetime import datetime


def gmt_to_timestamp(gmt_time):
    # convert object's last_modified(UTC TIME) to Unix Timestamp
    timestamp = datetime.strptime(gmt_time,
                                  '%a, %d %b %Y %H:%M:%S GMT')
    timestamp = calendar.timegm(timestamp.utctimetuple())
    return timestamp


def make_glacier_hidden_object_name(orig_info, glacier_key):
    keylength = len(glacier_key)
    return '%s-%s-%s' % (keylength, glacier_key, orig_info)


def get_glacier_key_from_hidden_object(hidden_obj):
    keylen = hidden_obj.split('-', 1)[0]
    startpoint = len(keylen)+1
    return hidden_obj[startpoint:int(keylen)+startpoint]


def get_glacier_objname_from_hidden_object(hidden_obj):
    keylen = hidden_obj.split('-', 1)[0]
    startlen = len(keylen)+int(keylen)+2
    return hidden_obj[startlen:]
