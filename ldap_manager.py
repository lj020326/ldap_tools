
import logging
import re
import pprint

import ldap

log = logging.getLogger(__name__)

class LdapManager(object):

    ldap_server = None
    ldap_admin_group = None
    ldap_uid_field = None
    ldap_search_base = None
    ldap_allow_self_signed = None

    ldap_conn = None
    ldap_conn_authuser = None

    def __init__(self, ldap_server, admin_dn, admin_password, search_base=None, allow_self_signed=False, uid_field="uid"):
        self.ldap_server=ldap_server
        self.ldap_search_base=search_base
        self.ldap_allow_self_signed=allow_self_signed
        self.ldap_uid_field=uid_field
        self.ldap_conn = None
        self.ldap_conn_authuser = None

        try:
            log.info("**** create ldap admin connection for LDAP record lookups")
            if self.ldap_allow_self_signed:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
            self.ldap_conn = ldap.initialize(self.ldap_server)
            self.ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

            # Authenticate admin user
            self.ldap_conn.simple_bind_s(admin_dn, admin_password)

            log.info("**** create ldap connection for user binds to LDAP")
            self.ldap_conn_authuser = ldap.initialize(self.ldap_server)
            self.ldap_conn_authuser.set_option(ldap.OPT_REFERRALS, 0)

        except ldap.LDAPError, e:
            if type(e.message) == dict and 'desc' in e.message:
                error_msg="Error in LDAP bind [%s]" % e.message['desc']
                log.error(error_msg)
                raise
            else:
                log.error("Error in LdapManager initialization [%s]" % e)
                raise


    def search_ldap_record(self, filter_str, base_dn=None, retrieve_attributes = None):
        """
            Searches LDAP for records

            :param filter_str: filter used to search
            :param base_dn: The ldap search base_dn
            :param retrieve_attributes: attributes to return - all if set to None
            :return: ldap object array
        """
        ldap_records = self.ldap_conn.search_s(base_dn,
                            ldap.SCOPE_SUBTREE,
                            filter_str,
                            retrieve_attributes)

        return ldap_records


    def get_ldap_user(self, userid, base_dn=None, retrieve_attributes=None, objectClass='organizationalPerson'):
        """
            Gets LDAP record for user.
            :param userid: userid to match with auth_ldap_uid_field
            :param base_dn: The ldap search base_dn
            :param retrieve_attributes: attributes to return - all if set to None
            :return: ldap object array
        """
        if objectClass:
            filter_str = "(&(objectClass=%s)" % objectClass
            filter_str += "(%s=%s))" % (self.ldap_uid_field, userid)
        else:
            filter_str = "%s=%s" % (self.ldap_uid_field, userid)

        if base_dn is None:
            base_dn=self.ldap_search_base

        log.debug("filter_str=[%s]" % filter_str)
        # log.debug("filter_str=[%s]" % filter_str)
        user = self.ldap_conn.search_s(base_dn,
                                    ldap.SCOPE_SUBTREE,
                                    filter_str,
                                    retrieve_attributes)
        if user:
            if not user[0][0]:
                return None
        return user

    def get_ldap_records(self, filter, base_dn=None, retrieve_attributes=None, objectClass='organizationalPerson'):
        """
            Gets LDAP record for user.
            :param filter: filter to query
            :param base_dn: The ldap search base_dn
            :param retrieve_attributes: attributes to return - all if set to None
            :return: ldap object array
        """

        if base_dn is None:
            base_dn=self.ldap_search_base

        log.debug("filter_str=[%s]" % filter)
        # log.debug("filter_str=[%s]" % filter_str)
        ldap_recordset = self.ldap_conn.search_s(base_dn,
                                    ldap.SCOPE_SUBTREE,
                                    filter,
                                    retrieve_attributes)
        return ldap_recordset

    def get_ldap_recordset(self, filter, base_dn=None, retrieve_attributes=None):
        """
            Gets native python object/dictionary representation for LDAP user record.
            :param filter: LDAP filter to query
            :param base_dn: The ldap search base_dn
            :param retrieve_attributes: attributes to return - all if set to None
            :return: ldap object array
        """
        ldap_recordset_raw = self.get_ldap_records(filter,base_dn,retrieve_attributes)

        if not ldap_recordset_raw:
            log.warning("Could not find any records for filter [%s]" % filter)
            return None

        ldap_recordset=[]
        for ldap_record in ldap_recordset_raw:
            (dn, ldap_record_detail) = ldap_record
            ldap_record = self.get_ldap_dict(ldap_record_detail)

            ldap_recordset.append(ldap_record)

        return ldap_recordset


    def get_ldap_userinfo(self, userid, base_dn=None, retrieve_attributes=None):
        """
            Gets native python object/dictionary representation for LDAP user record.
            :param username: username to match with auth_ldap_uid_field
            :param base_dn: The ldap search base_dn
            :param retrieve_attributes: attributes to return - all if set to None
            :return: ldap object array
        """
        ldap_user_recordset = self.get_ldap_user(userid,base_dn,retrieve_attributes)

        if not ldap_user_recordset:
            log.warning("Could not find user [%s]" % userid)
            return None

        (dn, ldap_user_record) = ldap_user_recordset[0]

        ldap_user = self.get_ldap_dict(ldap_user_record)

        return ldap_user


    def authenticate_user(self, userid, password):
        user_dn = "cn=%s,%s" % (userid, base_dn)
        return authenticate_user_dn(user_dn, password)

    def authenticate_user_dn(self, user_dn, password):

        try:
            # Authenticate user
            log.debug("binding for user_dn [%s]" % user_dn)
            if not self.ldap_conn_authuser.simple_bind_s(user_dn, password):
                log.error("Failed to bind to ldap for admin user_dn [%s]" % user_dn)
                return None

            self.ldap_conn_authuser.unbind_s()

            ldap_user=self.get_ldap_userinfo(userid)

            return ldap_user

        except ldap.LDAPError as e:
            if type(e.message) == dict and 'desc' in e.message:
                log.error("Error in LDAP bind [%s]" % e.message['desc'])
                return None
            else:
                log.error(e)
                return None

    @staticmethod
    def get_ldap_dict(ldap_record):
        ldap_info = {}

        for field in ldap_record.keys():
            try:
                ldap_info[field] = ldap_record[field][0] if len(ldap_record[field]) == 1 else ldap_record[field]
            except:
                ldap_info[field] = None

        return ldap_info


    def get_ad_groups(self, ldap_user):
        """ evaluate ADS group memberships """
        membership=ldap_user['memberOf']
        log.debug("Evaluating group membership")

        ad_groups = []

        if not membership:
            return ad_groups

        pattern = re.compile(r'^CN=(?P<groupName>[\w|\d|\s|-]+),')  #Our AD groups were mirrored with the flask app groups
        for group_dn in membership:
            # log.debug("group_dn = [%s]" % group_dn)
            groupMatch = pattern.match(group_dn)
            if groupMatch:
                group_name = groupMatch.group('groupName')
                log.debug("group_name = [%s]" % group_name)
                thisGroup = { 'name': group_name, 'ad_group_dn': group_dn }
                ad_groups.append(thisGroup)

        return ad_groups


    @staticmethod
    def get_list_diff(list1, list2):
        c = set(list1).union(set(list2))
        d = set(list1).intersection(set(list2))
        return list(c - d)

