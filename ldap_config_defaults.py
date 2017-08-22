
import os
import sys
import imp
import getpass
import traceback

from datetime import datetime as dt

print("setting default configs")

ldap_url="ldaps://localhost:636/"
ldap_user=getpass.getuser()
base_dn = 'OU=Users,DC=corp,DC=example,DC=org'
admin_bind_dn='cn=%s,%s' % (ldap_user,base_dn)
admin_pwd=None
ldap_user_id='cn'

ldap_query_chunk_size=10

data_dir='data'
file_in = 'test.xls'
file_in_path = '%s/%s' % (data_dir,file_in)

timestr=dt.now().strftime("%Y%m%d-%H%M%S.%f")[:-3]
file_out=file_in_path.split('.')[0] + '-out.%s' % timestr

CONFIG_PATH_ENV_VAR='LDAP_CONFIG_PATH'

try:
    if CONFIG_PATH_ENV_VAR in os.environ:
        # Explicitly import config module that is not in pythonpath; useful
        # for case where app is executed via external agent
        imp.load_source('ldap_config', os.environ[CONFIG_PATH_ENV_VAR])

    print('setting LOCAL configuration')
    from ldap_config import *  # noqa
    print('Loaded LOCAL configuration')
except ImportError, e:
    print("module not found: %s" % e)
    pass
except Exception, e:
    print("Exception in custom config:")
    print('-',-60)
    traceback.print_exc(file=sys.stdout)
    print('-',-60)
    raise e


if not admin_pwd:
    admin_pwd = getpass.getpass("enter password for user [%s] : " % ldap_user)
