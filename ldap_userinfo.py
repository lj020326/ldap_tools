
# from IPython.core.interactiveshell import InteractiveShell
# InteractiveShell.ast_node_interactivity = "all"
# InteractiveShell.log_level = 'INFO'
#
# from IPython.core.display import display, HTML
# display(HTML("<style>.container { width:100% !important; }</style>"))
#
# %matplotlib inline

import pandas as pd
import numpy as np
import logging
import sys
import ldap
import getpass
import json
# import codecs
from pprint import pprint
from datetime import datetime as dt

# import ldap_config as cfg
from ldap_config_defaults import *

from ldap_manager import LdapManager

from collections import OrderedDict

# reload(sys)
# sys.setdefaultencoding('utf8')


## ref: https://stackoverflow.com/questions/25699439/how-to-iterate-over-consecutive-chunks-of-pandas-dataframe-efficiently
def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


from json import JSONEncoder

class Utf8Encoder(JSONEncoder):
    # def default(self, o):
    #     # return o.__dict__
    #     if isinstance(obj, complex):
    #         return [obj.real, obj.imag]
    #     # Let the base class default method raise the TypeError
    #     return json.JSONEncoder.default(self, obj)

    def encode(self, data):
        # log.debug("encoding object type %s with value [%s]" % (data.__class__.__name__, data))
        if isinstance(data, unicode):
            return data.encode('utf-8')
        # if this is a list of values, return list of encoded values
        if isinstance(data, list):
            return [ self.encode(item) for item in data ]
        # if this is a dictionary, return dictionary of byteified keys and values
        # but only if we haven't already encoded it
        if isinstance(data, dict):
            return {
                # _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
                # _byteify(key): _byteify(value, ignore_dicts=True)
                self.encode(key): self.encode(value)
                for key, value in data.iteritems()
            }
        # if it's anything else, return it in its original form
        return data


def get_ldapinfo(record, ldap_mgr, ldap_fields):
    username=record.name
    ldap_user=ldap_mgr.get_ldap_userinfo(username)

    if not ldap_user:
        log.warning("Could not find user [%s]" % username)
        log.debug("return list of size %d" % len(ldap_fields))
        num_fields=len(ldap_fields)
        # return None, None, None
        # return (None,) * num_fields
        # return [None for x in range(num_fields)]
        return record

    log.debug("convert ldap_user values to utf-8")
    serialized=json.dumps(ldap_user, cls=Utf8Encoder) if 'ldap_userinfo_json' in ldap_fields else None

    if serialized:
        record['ldap_userinfo_json']=serialized

    for field in ldap_fields:
        value = ldap_user[field] if field in ldap_user.keys() else None
        record[field]=value

    log.debug( "return record=[%s]" % record)
    return record


log = logging.getLogger()
log.handlers = []
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)
log.addHandler(ch)

pd.set_option('display.width', 1000)
# pd.set_option('max_colwidth',200)
pd.reset_option('max_colwidth')

xls_file = pd.ExcelFile(file_in_path)

log.info("xls_file.sheet_names=%s" % xls_file.sheet_names)

frames=[]

for sheet in xls_file.sheet_names:
    log.info("loading sheet=[%s]" % sheet)
    #     df = xls_file.parse(sheet, header=None)
    df = xls_file.parse(sheet)
    frames.append(df)


df_result = pd.concat(frames)

log.info("[raw] df_result.shape=%s" % str(df_result.shape))
log.debug("[raw] df_result=\n%s" % df_result)

log.info("grouping by username")
strJoin = lambda x:",".join(x.astype(str))
df_grouped=df_result.groupby('USERNAME')

## ref: https://pandas.pydata.org/pandas-docs/stable/groupby.html
# df_result=df_grouped.agg({'GRANTED_ROLE': strJoin, 'LAST_LOGIN': np.max})
df_result=df_grouped.agg(OrderedDict([('GRANTED_ROLE', strJoin), ('LAST_LOGIN', np.max)]))

log.info("[clean] df_result.shape=%s" % str(df_result.shape))
log.debug("[clean] df_result=\n%s" % df_result)

log.info("getting user info from ldap")

log.info("using user account [%s] to bind to ldap" % ldap_user)

log.info("initializing ldap")

# ldap_mgr = ldap_mgr.LdapManager(ldap_url, admin_bind_dn, admin_pwd,search_base=base_dn)
ldap_mgr = LdapManager(ldap_url, admin_bind_dn, admin_pwd,search_base=base_dn)

ldap_fields = ['cn', 'description', 'mail', 'department', 'manager']
df_result = df_result.apply(lambda row: get_ldapinfo(row, ldap_mgr, ldap_fields), axis=1)

log.info("[post ldap] df_result.shape=%s" % str(df_result.shape))
log.debug("[post ldap] df_result=\n%s" % df_result)

import re
def split_it(displayName):
    x = re.findall('(\w+)', displayName)
    if x :
      return(x.group())

# df_result['usergroup'] = df_result['displayName'].apply(lambda x: split_it(x))
# df_result['usergroup'] = df_result['displayName'].apply(split_it)

df_result['usergroup']=df_result['description'].str.extract('\w+\((?P<UserGroup>\w+)\)\w+', expand=True)

log.info("[post derived] df_result.shape=%s" % str(df_result.shape))
log.debug("[post derived] df_result=\n%s" % df_result)

log.info("writing results to excel file [%s]" % file_out)

writer = pd.ExcelWriter(file_out)
df_result.to_excel(writer,'Sheet1')
writer.save()

log.info("done")
