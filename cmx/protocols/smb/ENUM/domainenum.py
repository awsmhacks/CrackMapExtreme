#!/usr/bin/env python3

###############################################################################

     #     # ####### #######        ####### #     # #     # #     # 
     ##    # #          #           #       ##    # #     # ##   ## 
     # #   # #          #           #       # #   # #     # # # # # 
     #  #  # #####      #    #####  #####   #  #  # #     # #  #  # 
     #   # # #          #           #       #   # # #     # #     # 
     #    ## #          #           #       #    ## #     # #     # 
     #     # #######    #           ####### #     #  #####  #     # 


###############################################################################
###############################################################################
#   Network/Domain Enum functions
#
# This section:
#   shares
#   pass_pol
#   groups
#   users
#   computers
#
###############################################################################

def shares(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    temp_dir = ntpath.normpath("\\" + gen_random_string())
    permissions = []
    #self.logger.announce('Starting Share Enumeration')

    try:
        for share in self.conn.listShares():
            share_name = share['shi1_netname'][:-1]
            share_remark = share['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark, 'access': []}
            read = False
            write = False

            try:
                self.conn.listPath(share_name, '*')
                read = True
                share_info['access'].append('READ')
            except SessionError:
                pass

            try:
                self.conn.createDirectory(share_name, temp_dir)
                self.conn.deleteDirectory(share_name, temp_dir)
                write = True
                share_info['access'].append('WRITE')
            except SessionError:
                pass

            permissions.append(share_info)
            #self.db.add_share(hostid, share_name, share_remark, read, write)

        #self.logger.debug('Enumerated shares')
        self.logger.success('Shares enumerated on: {}'.format(self.host))

        self.logger.highlight('{:<15} {:<15} {}'.format('Share', 'Permissions', 'Remark'))
        self.logger.highlight('{:<15} {:<15} {}'.format('-----', '-----------', '------'))
        for share in permissions:
            name   = share['name']
            remark = share['remark']
            perms  = share['access']

            self.logger.highlight('{:<15} {:<15} {}'.format(name, ','.join(perms), remark))

    except Exception as e:
        self.logger.error('Error enumerating shares: {}'.format(e))

    #self.logger.announce('Finished Share Enumeration')
    return permissions


def pass_pol(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    return PassPolDump(self).dump()


@requires_dc
def groups(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """

    if self.args.groups: targetGroup = self.args.groups
    groupFound = False
    groupLog = ''
    #self.logger.announce('Starting Domain Group Enum')

    try:
        rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password, domain=self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net groups Binding start')
            dce.bind(samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up reachable domain(s)')
                resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Domain Groups enumerated')
                self.logger.highlight("    {} Domain Group Accounts".format(tmpdomain))

                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                        if self.debug:
                            resp.dump()

                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    for group in resp['Buffer']['Buffer']:
                        gid = group['RelativeId']
                        r = samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                        #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                        logging.debug('Dump of hSamrQueryInformationGroup response:')
                        if self.debug:
                            info.dump()

                        #self.logger.results('Groupname: {:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        #print('')
                        self.logger.highlight('{:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        groupLog += '{:<30}  membercount: {}\n'.format(group['Name'], info['Buffer']['General']['MemberCount'])

                        samr.hSamrCloseHandle(dce, r['GroupHandle'])

                    enumerationContext = resp['EnumerationContext'] 
                    status = resp['ErrorCode']

            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Domain Groups')
                dce.disconnect()
                return
        except Exception as e: #failed bind
            logging.debug('failed bind {}'.format(str(e)))
            dce.disconnect()
            return
    except Exception as e: #failed connect
        logging.debug('failed connect {}'.format(str(e)))
        dce.disconnect()
        return

    try:
        dce.disconnect()
    except:
        pass

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Groups_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(groupLog), log_name)
        self.logger.announce("Saved Group Members output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Group Enum')
    return


@requires_dc
def users(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    users = ''
    #self.logger.announce('Starting Domain Users Enum')

    try:
        rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('NetUsers Binding start')
            dce.bind(samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up domain name(s)')
                resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                self.logger.debug('Looking up users in domain:'+ domains[0]['Name'])
                resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Domain Users enumerated')
                self.logger.highlight("     {} Domain User Accounts".format(tmpdomain))

                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateUsersInDomain response:')
                        if self.debug:
                            resp.dump()

                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    for user in resp['Buffer']['Buffer']:
                        r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here: 
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                        #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                        self.logger.highlight('{}\\{:<20}  rid: {}'.format(tmpdomain, user['Name'], user['RelativeId']))
                        users += '{}\\{:<20}  rid: {}\n'.format(tmpdomain, user['Name'], user['RelativeId'])

                        self.db.add_user(self.domain, user['Name'])

                        info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        samr.hSamrCloseHandle(dce, r['UserHandle'])

                    enumerationContext = resp['EnumerationContext'] 
                    status = resp['ErrorCode']

            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Domain Users')
                dce.disconnect()
                return list()
        except Exception as e: #failed bind
            logging.debug('failed bind {}'.format(str(e)))
            dce.disconnect()
            return list()
    except Exception as e: #failed connect
        logging.debug('failed connect {}'.format(str(e)))
        dce.disconnect()
        return list()

    try:
        dce.disconnect()
    except:
        pass

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Users_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(users), log_name)
        self.logger.announce("Saved Domain Users output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Users Enum')
    return list()

@requires_dc
def computers(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    comps = ''
    #self.logger.announce('Starting Domain Computers Enum')

    try:
        rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('NetUsers Binding start')
            dce.bind(samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up domain name(s)')
                resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                self.logger.debug('Looking up users in domain:'+ domains[0]['Name'])
                resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumerationContext = 0

                while status == STATUS_MORE_ENTRIES:
                    try:
                        #need one for workstations and second gets the DomainControllers
                        respComps = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                        respServs = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_SERVER_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                        
                        logging.debug('Dump of hSamrEnumerateUsersInDomain Comps response:')
                        if self.debug:
                            respComps.dump()
                        logging.debug('Dump of hSamrEnumerateUsersInDomain Servs response:')
                        if self.debug:
                            respServs.dump()

                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    self.logger.success('Domain Controllers enumerated')
                    self.logger.highlight("      {} Domain Controllers".format(tmpdomain))
                    comps += 'Domain Controllers  \n'

                    for user in respServs['Buffer']['Buffer']:
                        #servers
                        r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here: 
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                        self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                        comps += '{:<23} rid: {} \n'.format(user['Name'], user['RelativeId'])

                        #def add_computer(self, ip='', hostname='', domain=None, os='', dc='No'):
                        self.db.add_computer(hostname=user['Name'][:-1], domain=tmpdomain, dc='Yes')

                        info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        samr.hSamrCloseHandle(dce, r['UserHandle'])


                    print('')
                    self.logger.success('Domain Computers enumerated')
                    self.logger.highlight("      {} Domain Computer Accounts".format(tmpdomain))
                    comps += '\nDomain Computers \n'


                    for user in respComps['Buffer']['Buffer']:
                        #workstations
                        r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here: 
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                        #self.logger.results('Computername: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                        self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                        comps += '{:<23} rid: {}\n'.format(user['Name'], user['RelativeId'])

                        #def add_computer(self, ip='', hostname='', domain=None, os='', dc='No'):
                        self.db.add_computer(hostname=user['Name'][:-1], domain=tmpdomain)

                        info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        samr.hSamrCloseHandle(dce, r['UserHandle'])


                    enumerationContext = respComps['EnumerationContext'] 
                    status = respComps['ErrorCode']

            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Domain Computers')
                dce.disconnect()
                return
        except Exception as e: #failed bind
            logging.debug('failed bind {}'.format(str(e)))
            dce.disconnect()
            return
    except Exception as e: #failed connect
        logging.debug('failed connect {}'.format(str(e)))
        dce.disconnect()
        return

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Computers_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(comps), log_name)
        self.logger.announce("Saved Domain Computers output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Computer Enum')
    return


@requires_dc
def group(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    targetGroup = self.args.group
    groupFound = False
    groupLog = ''
    
    if targetGroup == '':
        self.logger.error("Must specify a group name after --group ")
        return list()

    #self.logger.announce('Starting Domain Group Enum')

    try:
        rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password, domain=self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net groups Binding start')
            dce.bind(samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up reachable domain(s)')
                resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = STATUS_MORE_ENTRIES
                enumerationContext = 0

                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                        if self.debug:
                            resp.dump()

                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    for group in resp['Buffer']['Buffer']:
                        gid = group['RelativeId']
                        r = samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                        #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                        logging.debug('Dump of hSamrQueryInformationGroup response:')
                        if self.debug:
                            info.dump()

                        if group['Name'] == targetGroup:
                            self.logger.success('\"{}\" Domain Group Found in {}'.format(targetGroup, tmpdomain))
                            self.logger.highlight("    \"{}\" Group Info".format(targetGroup))
                            groupFound = True
                            self.logger.highlight('Member Count: {}'.format(info['Buffer']['General']['MemberCount']))

                            groupResp = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                            logging.debug('Dump of hSamrGetMembersInGroup response:')
                            if self.debug:
                                groupResp.dump()

                            for member in groupResp['Members']['Members']:
                                m = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, member)
                                guser = samr.hSamrQueryInformationUser2(dce, m['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                groupLog += '{}\\{:<30}  \n'.format(tmpdomain, guser['Buffer']['All']['UserName'])
                            
                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()

                    if groupFound == False:
                        self.logger.error("Specified group was not found")
                        samr.hSamrCloseHandle(dce, r['GroupHandle'])


                    enumerationContext = resp['EnumerationContext'] 
                    status = resp['ErrorCode']

            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Domain Groups')
                dce.disconnect()
                return
        except Exception as e: #failed bind
            logging.debug('failed bind {}'.format(str(e)))
            dce.disconnect()
            return
    except Exception as e: #failed connect
        logging.debug('failed connect {}'.format(str(e)))
        dce.disconnect()
        return

    try:
        dce.disconnect()
    except:
        pass

    if self.args.logs and groupFound:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Members_of_{}_on_{}.log'.format(targetGroup, ctime)
        write_log(str(groupLog), log_name)
        self.logger.announce("Saved Group Members output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Group Enum')
    return

