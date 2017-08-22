
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
import json
from math import ceil
import argh
import traceback

from datetime import datetime as dt

import ldap_config_defaults as configs
# from ldap_config_defaults import *

from ldap_manager import LdapManager

from collections import OrderedDict

## ref: https://stackoverflow.com/questions/25699439/how-to-iterate-over-consecutive-chunks-of-pandas-dataframe-efficiently
def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


from json import JSONEncoder

log = logging.getLogger()
log.handlers = []
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.setLevel(configs.loglevel)
log.addHandler(ch)

ldap_mgr = LdapManager(configs.ldap_url, configs.admin_bind_dn, configs.admin_pwd, search_base=configs.base_dn, uid_field=configs.ldap_user_id)

pd.set_option('display.width', 1000)
# pd.set_option('max_colwidth',200)
pd.reset_option('max_colwidth')


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



def get_ldap_user_record(record, ldap_mgr, ldap_fields, df, uid_field=None):
    i=df.index.get_loc(record.name)
    if i % int(ceil(float(df.shape[0])/20)) == 0:
        pct_done=int((float(i)/df.shape[0])*100)
        log.info("get_ldap_user_record [%s%%] done, iteration [%s]" % (pct_done, i))

    username=record.name
    if uid_field:
        username=record[uid_field]

    ldap_user=ldap_mgr.get_ldap_userinfo(username)
    # log.debug("UTF8 encoding user info")
    # ldap_user=json.dumps(ldap_user, cls=Utf8Encoder)

    if not ldap_user:
        log.warning("Could not find user [%s]" % username)
        log.debug("return list of size %d" % len(ldap_fields))
        return record

    if 'ldap_userinfo_json' in ldap_fields:
        log.debug("convert ldap_user values to utf-8")
        serialized=json.dumps(ldap_user, cls=Utf8Encoder) if 'ldap_userinfo_json' in ldap_fields else None
        record['ldap_userinfo_json']=serialized

    for field in ldap_fields:
        value = ldap_user[field] if field in ldap_user.keys() else None
        record[field]=value

    log.debug( "return record=[%s]" % record)
    return record


def get_ldap_recordset(filter, ldap_mgr, ldap_fields):
    log.debug("get_ldap_recordset[%s]" % filter)

    ldap_recordset=ldap_mgr.get_ldap_recordset(filter, retrieve_attributes=ldap_fields)
    # log.debug("UTF8 encoding user info")
    # ldap_recordset=json.dumps(ldap_recordset, cls=Utf8Encoder)

    if not ldap_recordset:
        log.warning("Could not find any records for filter [%s]" % filter)
        log.debug("return list of size %d" % len(ldap_fields))
        return None

    df=pd.DataFrame(ldap_recordset)
    log.debug("[get_ldap_recordset] df.shape=%s" % str(df.shape))
    log.debug("[get_ldap_recordset] df=\n%s" % df)

    return df

def get_ldap_userset_chunked(df, ldap_fields, chunk_size=10):
    # df_ldap_results = pd.concat([df, pd.DataFrame(columns=ldap_fields)])
    # df_ldap_results = pd.DataFrame(index='cn', columns=ldap_fields_minus_cn)
    df_ldap_results = pd.DataFrame(columns=ldap_fields)
    df_ldap_results.set_index(configs.ldap_user_id, inplace=True)

    for df_chunk in chunker(df, chunk_size):
        log.debug("df_chunk.shape=%s" % str(df_chunk.shape))
        log.debug("df_chunk=\n%s" % df_chunk)

        # id_list = df_chunk['cn'].str.cat(sep=')(cn=')
        # id_list = df_chunk.index.str.cat(sep=')(cn=')
        delim=')(%s=' % configs.ldap_user_id
        id_list = df_chunk.index.str.cat(sep=delim)

        log.debug("id_list=%s" % id_list)

        filter="(&(objectClass=organizationalPerson)"
        filter+="(|(%s=%s)))" % (configs.ldap_user_id, id_list)

        log.debug("filter=%s" % filter)
        df_results = get_ldap_recordset(filter, ldap_mgr, ldap_fields)

        log.debug("df_results.shape=%s" % str(df_results.shape))
        log.debug("df_results=\n%s" % df_results)

        df_results.set_index(configs.ldap_user_id, inplace=True)
        df_results.index=df_results.index.str.upper()

        log.debug("df_results.shape=%s" % str(df_results.shape))
        log.debug("df_results=\n%s" % df_results)

        df_ldap_results=df_ldap_results.append(df_results, verify_integrity=True)
        log.debug("[post-append] df_ldap_results.shape=%s" % str(df_ldap_results.shape))
        log.debug("[post-append] df_ldap_results[df_ldap_results.index.isin(df_results.index)]=\n%s" % df_ldap_results[df_ldap_results.index.isin(df_results.index)])

    log.info("df_ldap_results.shape=%s" % str(df_ldap_results.shape))
    log.info("df_ldap_results.head(10)=\n%s" % df_ldap_results.head(10))
    return df_ldap_results


def get_ldap_userset(file_in_path=configs.file_in_path):

    log.info("loading file [%s]" % file_in_path)
    xls_file = pd.ExcelFile(file_in_path)

    log.info("xls_file.sheet_names=%s" % xls_file.sheet_names)

    frames=[]

    for sheet in xls_file.sheet_names:
        log.info("loading sheet=[%s]" % sheet)
        #     df = xls_file.parse(sheet, header=None)
        # df = xls_file.parse(sheet)
        # df = pd.read_excel('MC_simulation.xlsx', 'DataSet', encoding='utf-8')
        df = xls_file.parse(sheet, encoding='utf-8')
        frames.append(df)

    df = pd.concat(frames)

    log.info("[raw] df.shape=%s" % str(df.shape))
    log.debug("[raw] df.head(10)=\n%s" % df.head(10))

    dupe_cnt=df[df['USERNAME'].duplicated()].size
    log.info("df dupe count=%s" % dupe_cnt)
    if dupe_cnt>0:
        log.info("grouping by username")
        df_grouped=df.groupby('USERNAME')

        strJoin = lambda x:",".join(x.astype(str))
        ## ref: https://pandas.pydata.org/pandas-docs/stable/groupby.html
        # df=df_grouped.agg({'GRANTED_ROLE': strJoin, 'LAST_LOGIN': np.max})
        df=df_grouped.agg(OrderedDict([('GRANTED_ROLE', strJoin), ('LAST_LOGIN', np.max)]), as_index=False)
        df.reset_index(inplace=True)

    log.info("[clean] df.shape=%s" % str(df.shape))
    log.debug("[clean] df.head(10)=\n%s" % df.head(10))

    log.info("getting user info from ldap")

    log.info("using user account [%s] to bind to ldap" % configs.ldap_user)

    log.info("initializing ldap")

    ldap_fields = [configs.ldap_user_id,'displayName','description', 'mail', 'department', 'manager']

    log.info("setting dataframe index")
    df[configs.ldap_user_id]=df['USERNAME']
    # df['cn']=df.index
    df.set_index(configs.ldap_user_id, inplace=True)
    df.index = df.index.str.upper()

    log.info("[pre-ldap] df.shape=%s" % str(df.shape))
    log.info("[pre-ldap] df.head(10)=\n%s" % df.head(10))

    df_ldap_results=get_ldap_userset_chunked(df, ldap_fields, chunk_size=configs.ldap_query_chunk_size)
    df=df.join(df_ldap_results, rsuffix='_r')
    log.info("[post-join] df.head(10)=\n%s" % df.head(10))

    log.info("setting derived values")

    df['usergroup']=df['description'].str.extract('\w+ \((?P<UserGroup>\w.*)\)', expand=True)
    df['manager_id']=df['manager'].str[3:10].str.upper()
    # df['manager_name']=df.join(df, on='manager_id', rsuffix='_mgr')['description_mgr']

    log.info("[post derived] df.shape=%s" % str(df.shape))
    log.debug("[post derived] df=\n%s" % df)

    log.info("getting manager names")
    df = get_manager_names(df)

    # ref: http://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.str.get_dummies.html
    # ref: https://stackoverflow.com/questions/23208745/python-pandas-add-dummy-columns-to-the-original-dataframe
    df = pd.concat([df, df['GRANTED_ROLE'].str.get_dummies(sep=',')], axis=1)

    # csv_store='%s/results.csv' % configs.data_dir
    csv_store='%s.csv' % configs.file_out
    log.info("writing results to [%s]" % csv_store)
    df.to_csv(csv_store, encoding='utf-8')

    try:
        df_tmp = pd.read_csv(csv_store, encoding='utf-8')
        log.info("writing results to [%s]" % configs.file_out)
        # df.to_excel(file_out, encoding='utf-8')
        xls_store='%s.xls' % configs.file_out
        df_tmp.to_excel(xls_store)
    except  Exception as err:
        log.error("when writing to file %s - exception occurred %s" % (configs.file_out, err))
        traceback.print_exc()

    log.info("done")


def get_manager_names(df=None, csv_store=None):

    if csv_store:
        # csv_store='%s/results.csv' % data_dir
        log.info("loading file [%s]" % csv_store)

        df = pd.read_csv(csv_store, encoding='utf-8')

    log.info("df.shape=%s" % str(df.shape))

    df_mgr = pd.DataFrame(df.groupby('manager_id').groups.keys(),columns=['manager_id'])
    df_mgr.set_index('manager_id', inplace=True)

    log.info("df_mgr.shape=%s" % str(df_mgr.shape))
    # log.debug("df_mgr.columns = %s" % df_mgr.columns)
    log.debug("df_mgr=\n%s" % df_mgr)

    ldap_fields=[configs.ldap_user_id,'description','displayName']

    df_ldap_results=get_ldap_userset_chunked(df_mgr, ldap_fields, chunk_size=configs.ldap_query_chunk_size)
    df=df.join(df_ldap_results, rsuffix='_mgr', on='manager_id')
    df.loc[df['displayName_mgr'].isnull() == False, 'manager_name'] = df['displayName_mgr']
    df.drop(['description_mgr','displayName_mgr'], axis=1, inplace=True)
    log.info("[post-join] df.head(10)=\n%s" % df.head(10))

    return df


# assembling
parser=argh.ArghParser()
parser.add_commands([get_ldap_userset, get_manager_names])


if __name__ == "__main__":
    # dispatching
    parser.dispatch()


