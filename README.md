
Step 1: set configs

    ## copy/modify boilerplate config into ldap_config.py
    ## set ldap url and the ldap query user creds
    ## and update xls filename
    cp etc/ldap_config_dist.py ldap_config.py
    
Step 2: modify test data in xls

Step 3: run

    python ldap_info.py get_manager_names

