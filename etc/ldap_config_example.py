
import getpass
from datetime import datetime as dt

ldap_url=None
bind_dn=None
base_db=None
admin_bind_dn=None
admin_pwd=None

app_env='DEV'

loglevel='INFO'

# file_in = 'data/test-small.xls'
file_in = 'data/users.xlsx'

timestr=dt.now().strftime("%Y%m%d-%H%M%S.%f")[:-3]
file_out=file_in.split('.')[0] + '-out.%s' % timestr

if app_env=='DEV':
    ldap_url="ldap://localhost:389/"
    ldap_user='testuser'
    base_dn='OU=Users,DC=corp,DC=example,DC=org'
    admin_bind_dn='uid=%s,%s' % (ldap_user,base_dn)
    admin_pwd='letmein'
else:
    ldap_url="ldaps://corp.example.org:636/"
    ldap_user=getpass.getuser()
    base_dn='OU=Users,DC=corp,DC=example,DC=org'
    admin_bind_dn='cn=%s,%s' % (ldap_user,base_dn)
    admin_pwd = 'letmein'

