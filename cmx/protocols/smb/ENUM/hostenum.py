#!/usr/bin/env python3

###############################################################################

#     # #######  #####  #######       ####### #     # #     # #     # 
#     # #     # #     #    #          #       ##    # #     # ##   ## 
#     # #     # #          #          #       # #   # #     # # # # # 
####### #     #  #####     #    ##### #####   #  #  # #     # #  #  # 
#     # #     #       #    #          #       #   # # #     # #     # 
#     # #     # #     #    #          #       #    ## #     # #     # 
#     # #######  #####     #          ####### #     #  #####  #     # 

###############################################################################
###############################################################################
#    Host Enum Functions
#
# This section:
#   enum_host_info
#   disks
#   sessions
#   loggedon
#   local_users
#   local_groups
#   rid_brute
#   spider
#
####################################################################################

class HostEnum(smb):
    
    def enum_host_info(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login('' , '')
            logging.debug("Null login?")
            self.logger.success('Null login allowed')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                pass

        self.domain     = self.conn.getServerDomain()           # OCEAN
        self.hostname   = self.conn.getServerName()             # WIN7-PC
        self.server_os  = self.conn.getServerOS()               # WIndows 6.1 Build 7601
        self.signing    = self.conn.isSigningRequired()         # True/false
        self.os_arch    = self.get_os_arch()                    # 64
        self.domain_dns = self.conn.getServerDNSDomainName()    # ocean.depth

        self.logger.hostname = self.hostname   
        dialect = self.conn.getDialect()

        #print (self.conn.getServerDomain())            # OCEAN
        #print (self.conn.getServerName())              # WIN7-PC
        #print (self.conn.getServerOS())                # WIndows 6.1 Build 7601
        #print (self.conn.isSigningRequired())          # True
        #print (self.get_os_arch())                     # 64
        #print (self.conn.getDialect())                 # 528
        #print (self.conn.getRemoteHost())              # IPaddress
        #print (self.conn.getRemoteName())              # win7-pc
        #print (self.conn.getServerDNSDomainName())     # ocean.depth
        #print (self.conn.getServerOSMajor())           # 6
        #print (self.conn.getServerOSMinor())           # 1
        #print (self.conn.getServerOSBuild())           # 7601 
        #print (self.conn.doesSupportNTLMv2())          # True
        #print (self.conn.isLoginRequired())            # True

        if dialect == SMB_DIALECT:
            self.smbv = '1'
            logging.debug("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            self.smbv = '2.0'
            logging.debug("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            self.smbv = '2.1'
            logging.debug("SMBv2.1 dialect used")
        else:
            self.smbv = '3.0'
            logging.debug("SMBv3.0 dialect used")

        # Get the DC if we arent local-auth and didnt specify
        if not self.args.local_auth and self.dc_ip =='':
            self.dc_ip = self.conn.getServerDNSDomainName()

        if self.args.domain:
            self.domain = self.args.domain

        if not self.domain:
            self.domain = self.hostname

        self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)


        try:
            ''' DC's seem to want us to logoff first, windows workstations sometimes reset the connection
            '''
            self.conn.logoff()
        except:
            pass

        if self.args.local_auth:
            self.domain = self.hostname

        self.output_filename = '{}/{}_{}_{}'.format(cfg.LOGS_PATH,self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S"))
        #Re-connect since we logged off
        self.create_conn_obj()


    def disks(self):
        """Enumerate disks

        *** This does require local admin i think. Made to return nothing if not admin.

            
        Raises:
            
        Returns:

        """
        #self.logger.info('Attempting to enum disks...')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('disks Binding start')
                dce.bind(srvs.MSRPC_UUID_SRVS)
                try:
                    logging.debug('Get disks via hNetrServerDiskEnum...')
                    #self.logger.announce('Attempting to enum disks...')
                    resp = srvs.hNetrServerDiskEnum(dce, 0)  
                    self.logger.success('Disks enumerated on {} !'.format(self.host))

                    for disk in resp['DiskInfoStruct']['Buffer']:
                        if disk['Disk'] != '\x00':
                            #self.logger.results('Disk: {} found on {}'.format(disk['Disk'], self.host))
                            self.logger.highlight("Found Disk: {}\\ ".format(disk['Disk']))
                    return

                except Exception as e: #failed function
                    logging.debug('failed function {}'.format(str(e)))
                    self.logger.error('Failed to enum disks, are you LocalAdmin?')
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

        #self.logger.info('Finished disk enum')            
        dce.disconnect()
        return

    def sessions(self):
        """Enumerate sessions
        
        Using impackets hNetrSessionEnum from https://github.com/SecureAuthCorp/impacket/blob/ec9d119d102251d13e2f9b4ff25966220f4005e9/impacket/dcerpc/v5/srvs.py

        *** This was supposed to grab a list of all computers, then do session enum - or thats what it sounds like in impackets version
        Actually, looks at the target and identifes sessions and their originating host.
        
        Args:
            
        Raises:
            
        Returns:

        """
        #self.logger.announce('Starting Session Enum')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('netsessions Binding start')
                dce.bind(srvs.MSRPC_UUID_SRVS)
                try:
                    logging.debug('Get netsessions via hNetrSessionEnum...')
                    self.logger.success('Sessions enumerated on {} !'.format(self.host))
                    resp = srvs.hNetrSessionEnum(dce, '\x00', '\x00', 10)  #no clue why \x00 is used for client and username?? but it works!

                    for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                        userName = session['sesi10_username'][:-1]
                        sourceIP = session['sesi10_cname'][:-1][2:]
                        #self.logger.results('User: {} has session originating from {}'.format(userName, sourceIP))
                        self.logger.highlight("{} has session originating from {} on {}".format(userName, sourceIP, self.host,))
                    return

                except Exception as e: #failed function
                    logging.debug('failed function {}'.format(str(e)))
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

        #self.logger.announce('Finished Session Enum')
        dce.disconnect()
        return


    def loggedon(self):
        """
        
        I think it requires localadmin, but handles if it doesnt work.
        Args:
            
        Raises:
            
        Returns:

        """

        loggedon = []
        #self.logger.announce('Checking for logged on users')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\wkssvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('loggedon Binding start')
                dce.bind(wkst.MSRPC_UUID_WKST)
                try:
                    logging.debug('Get loggedonUsers via hNetrWkstaUserEnum...')
                    #self.logger.announce('Attempting to enum loggedon users...')
                    resp = wkst.hNetrWkstaUserEnum(dce, 1)   # theres a version that takes 0, not sure the difference?
                    self.logger.success('Loggedon-Users enumerated on {} !'.format(self.host))

                    for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                        wkst_username = wksta_user['wkui1_username'][:-1] # These are defined in https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/wkst.py#WKSTA_USER_INFO_1
                        #self.logger.results('User:{} is currently logged on {}'.format(wkst_username,self.host))
                        self.logger.highlight("{} is currently logged on {} ({})".format(wkst_username, self.host, self.hostname))

                    return

                except Exception as e: #failed function
                    logging.debug('failed function {}'.format(str(e)))
                    self.logger.error('Failed to enum Loggedon Users, are you localadmin?')
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

        #self.logger.announce('Finished checking for logged on users')
        dce.disconnect()
        return


    def local_users(self):
        """
        To enumerate local users
        
        Args:
            
        Raises:
            
        Returns:

        """
        users = []
        #self.logger.announce('Checking Local Users')

        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()

            try:
                logging.debug('net local users Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)

                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  

                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    
                    self.logger.debug('Looking up host name')
                    serverHandle = resp['ServerHandle'] 
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    logging.debug('Looking up localusers on: '+ domains[0]['Name'])
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

                    self.logger.success('Local Users enumerated on {} !'.format(self.host))
                    self.logger.highlight("   Local User Accounts")

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
                            #users
                            r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()
                            # r has the clases defined here: 
                                #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                            #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                            self.logger.highlight("{}\\{:<15} :{} ".format(self.hostname, user['Name'], user['RelativeId']))

                            self.db.add_user(self.hostname, user['Name'])

                            info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                info.dump()
                            samr.hSamrCloseHandle(dce, r['UserHandle'])
                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']

                except Exception as e: #failed function
                    logging.debug('failed function {}'.format(str(e)))
                    self.logger.error('Failed to enum Local Users, are you localadmin?')
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

        #self.logger.announce('Finished Checking Local Users')
        dce.disconnect()
        return
        

    def local_groups(self):
        """
        To enumerate local groups 
        
        Args:
            
        Raises:
            
        Returns:

        """
        groups = []
        #self.logger.announce('Checking Local Groups')

        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('Get net localgroups Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  

                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()

                    serverHandle = resp['ServerHandle'] 
                    self.logger.debug('Checking host name')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)

                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']
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
                    self.logger.success('Local Groups enumerated on: {}'.format(self.host))
                    self.logger.highlight("        Local Group Accounts")

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
                            self.logger.highlight('Group: {:<20}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))

                            groupResp = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                            logging.debug('Dump of hSamrGetMembersInGroup response:')
                            if self.debug:
                                groupResp.dump()

                            for member in groupResp['Members']['Members']:
                                m = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, member)
                                guser = samr.hSamrQueryInformationUser2(dce, m['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                
                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()

                            samr.hSamrCloseHandle(dce, r['GroupHandle'])
                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']

                except Exception as e: #failed function
                    logging.debug('failed function {}'.format(str(e)))
                    self.logger.error('Failed to enum Local Groups, are you localadmin?')
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

        #self.logger.announce('Finished Checking Local Groups')
        dce.disconnect()
        return


    def rid_brute(self, maxRid=None):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        entries = []
        #self.logger.announce('Starting RID Brute')
        
        if not maxRid:
            maxRid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
            139: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            445: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            }

        try:
            stringbinding = KNOWN_PROTOCOLS[self.args.port]['bindstr'].format(self.host)
            logging.debug('StringBinding {}'.format(stringbinding))
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.args.port)

            if KNOWN_PROTOCOLS[self.args.port]['set_host']:
                rpctransport.setRemoteHost(self.host)

            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
        except Exception as e:
            self.logger.error('Error creating DCERPC connection: {}'.format(e))
            return entries

        # Want encryption? Uncomment next line
        # But make SIMULTANEOUS variable <= 100
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        self.logger.debug('Brute forcing RIDs')
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        soFar = 0
        SIMULTANEOUS = 1000
        self.logger.success("RID's enumerated on: {}".format(self.host))
        self.logger.highlight("         RID Information")
        for j in range(maxRid//SIMULTANEOUS+1):
            if (maxRid - soFar) // SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else:
                sidsToCheck = SIMULTANEOUS

            if sidsToCheck == 0:
                break

            sids = list()
            for i in range(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    rid    = soFar + n
                    domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                    user   = item['Name']
                    sid_type = SID_NAME_USE.enumItems(item['Use']).name
                    self.logger.highlight("{}\\{:<15} :{} ({})".format(domain, user, rid, sid_type))
                    entries.append({'rid': rid, 'domain': domain, 'username': user, 'sidtype': sid_type})

            soFar += SIMULTANEOUS

        dce.disconnect()

        #self.logger.announce('Finished RID brute')
        return entries


    def spider(self, share=None, folder='.', pattern=[], regex=[], exclude_dirs=[], depth=None, content=False, onlyfiles=True):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.announce('Starting Spider')
        spider = SMBSpider(self.conn, self.logger)

        self.logger.announce('Started spidering')
        start_time = time()
        if not share:
            spider.spider(self.args.spider, self.args.spider_folder, self.args.pattern,
                          self.args.regex, self.args.exclude_dirs, self.args.depth,
                          self.args.content, self.args.only_files)
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, onlyfiles)

        self.logger.announce("Done spidering (Completed in {})".format(time() - start_time))

        self.logger.announce('Finished Spidering')
        return spider.results


