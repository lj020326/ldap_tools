
# from IPython.core.interactiveshell import InteractiveShell
# InteractiveShell.ast_node_interactivity = "all"
# InteractiveShell.log_level = 'INFO'
#
# from IPython.core.display import display, HTML
# display(HTML("<style>.container { width:100% !important; }</style>"))
#
# %matplotlib inline

# import argparse
import argh
# import sys

import pandas as pd
import numpy as np
import logging
import json
from math import ceil

from datetime import datetime as dt

# import ldap_config as cfg
from ldap_config_defaults import *

from ldap_manager import LdapManager

from collections import OrderedDict
from json import JSONEncoder

import Crypto.Random
from Crypto.Cipher import AES
import hashlib

# salt size in bytes
SALT_SIZE = 16

# number of iterations in the key generation
NUMBER_OF_ITERATIONS = 200

# the size multiple required for AES
AES_MULTIPLE = 16

KEYSTORE_PWD = "OCvk6ARpod1Pnu4sSuPa"

log = logging.getLogger()
log.handlers = []
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.setLevel(loglevel)
log.addHandler(ch)

pd.set_option('display.width', 1000)
# pd.set_option('max_colwidth',200)
pd.reset_option('max_colwidth')


## ref: https://stackoverflow.com/questions/25699439/how-to-iterate-over-consecutive-chunks-of-pandas-dataframe-efficiently
def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


def generate_key(password, salt, iterations):
    assert iterations > 0

    key = password + salt
    for i in range(iterations):
        key = hashlib.sha256(key).digest()

    return key


def pad_text(text, multiple):
    extra_bytes = len(text) % multiple

    padding_size = multiple - extra_bytes
    padding = chr(padding_size) * padding_size
    padded_text = text + padding

    return padded_text


def unpad_text(padded_text):
    padding_size = ord(padded_text[-1])

    text = padded_text[:-padding_size]

    return text


def encrypt(plaintext, password):
    salt = Crypto.Random.get_random_bytes(SALT_SIZE)

    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad_text(plaintext, AES_MULTIPLE)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_with_salt = salt + ciphertext

    return ciphertext_with_salt

def gen_key(password, key_file=None):
    if key_file:
        with open(key_file, "wt") as out_file:
            out_file.write("[license]\n" + hostname + " = " + iouLicense + ";\n")
        log.info("created key file [%s]" % key_file)
        return

    return encrypt(password, KEYSTORE_PWD)

def get_password(cyphertext):
    return decrypt(cyphertext, KEYSTORE_PWD)


def decrypt(ciphertext, password):
    salt = ciphertext[0:SALT_SIZE]

    ciphertext_sans_salt = ciphertext[SALT_SIZE:]
    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext_sans_salt)
    plaintext = unpad_text(padded_plaintext)

    return plaintext


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


def get_ldap_userinfo(record, ldap_mgr, ldap_fields, df):
    i=df.index.get_loc(record.name)
    if i % int(ceil(float(df.shape[0])/20)) == 0:
        pct_done=int((float(i)/df.shape[0])*100)
        log.info("get_ldapinfo [%s%%] done, iteration [%s]" % (pct_done, i))

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

    if 'ldap_userinfo_json' in ldap_fields:
        log.debug("convert ldap_user values to utf-8")
        serialized=json.dumps(ldap_user, cls=Utf8Encoder) if 'ldap_userinfo_json' in ldap_fields else None
        record['ldap_userinfo_json']=serialized

    for field in ldap_fields:
        value = ldap_user[field] if field in ldap_user.keys() else None
        record[field]=value

    log.debug( "return record=[%s]" % record)
    return record


def get_ldap_userset(file_in_path=file_in_path):
    "load user ids from file and retrieve ldap info for each."
    log.info("loading file [%s]" % file_in_path)
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

    log.info("df_results dupe count=%s" % df_result[df_result['USERNAME'].duplicated()].size)
    if df_result[df_result['USERNAME'].duplicated()].size>0:
        log.info("grouping by username")
        df_grouped=df_result.groupby('USERNAME')

        strJoin = lambda x:",".join(x.astype(str))
        ## ref: https://pandas.pydata.org/pandas-docs/stable/groupby.html
        # df_result=df_grouped.agg({'GRANTED_ROLE': strJoin, 'LAST_LOGIN': np.max})
        df_result=df_grouped.agg(OrderedDict([('GRANTED_ROLE', strJoin), ('LAST_LOGIN', np.max)]))

    log.info("[clean] df_result.shape=%s" % str(df_result.shape))
    log.debug("[clean] df_result=\n%s" % df_result)

    log.info("binding to ldap with user [%s] for running queries" % ldap_user)
    log.info("initializing ldap")

    # ldap_mgr = ldap_mgr.LdapManager(ldap_url, admin_bind_dn, admin_pwd,search_base=base_dn)
    ldap_mgr = LdapManager(ldap_url, admin_bind_dn, admin_pwd,search_base=base_dn)

    log.info("getting user info from ldap")
    ldap_fields = ['cn', 'description', 'mail', 'department', 'manager']
    # df_result = df_result.apply(get_ldapinfo, ldap_mgr, ldap_fields, df_result, axis=1)
    df_result = df_result.apply(lambda row: get_ldap_userinfo(row, ldap_mgr, ldap_fields, df_result), axis=1)

    log.info("[post ldap] df_result.shape=%s" % str(df_result.shape))
    log.debug("[post ldap] df_result=\n%s" % df_result)

    df_result['usergroup']=df_result['description'].str.extract('\w+ \((?P<UserGroup>\w.*)\)', expand=True)

    log.info("[post derived] df_result.shape=%s" % str(df_result.shape))
    log.debug("[post derived] df_result=\n%s" % df_result)

    log.info("writing results to excel file [%s]" % file_out)

    writer = pd.ExcelWriter(file_out)
    # df_result.to_excel(writer,'Sheet1')
    df_result.to_excel(writer,'Sheet1', encoding='utf8')
    writer.save()

    log.info("done")


def main():

    # ref: https://pypi.python.org/pypi/argh
    # assembling:
    parser = argh.ArghParser()
    parser.add_commands([get_ldap_userset, gen_key])

    # dispatching:
    parser.dispatch()


if __name__ == "__main__":
    main()

