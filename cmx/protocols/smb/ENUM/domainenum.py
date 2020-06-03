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
from cmx.connection import *
import impacket
from datetime import datetime
import cmx
from cmx.helpers.logger import highlight, write_log
from cmx import config as cfg
import pdb

def pass_pol(self):
    """
    
    Args:
        
    Raises:
        
    Returns:

    """
    return PassPolDump(self).dump()


def group1(smb):
    """Enum domain groups.

    Prints output and adds them to cmxdb
    """
    self = smb

    if self.args.groups:
        targetGroup = self.args.groups

    groupFound = False
    groupLog = ''
    #self.logger.announce('Starting Domain Group Enum')

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password) #domain=self.domain
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net groups Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up reachable domain(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Domain Groups enumerated')
                self.logger.highlight("    {} Domain Group Accounts".format(tmpdomain))

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        resp = impacket.dcerpc.v5.samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                        if self.debug:
                            resp.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    for group in resp['Buffer']['Buffer']:
                        gid = group['RelativeId']
                        r = impacket.dcerpc.v5.samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],impacket.dcerpc.v5.samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                        #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                        logging.debug('Dump of hSamrQueryInformationGroup response:')
                        if self.debug:
                            info.dump()

                        #self.logger.results('Groupname: {:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        #print('')
                        self.logger.highlight('{:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        groupLog += '{:<30}  membercount: {}\n'.format(group['Name'], info['Buffer']['General']['MemberCount'])

                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['GroupHandle'])

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
        logging.debug('failed connect in group1.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in group1.a')
            pass
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

def group1_full(smb):
    """Enum domain groups and display their members

    Prints output and adds them to cmxdb
    """
    self = smb

    if self.args.groups:
        targetGroup = self.args.groups

    groupFound = False
    groupLog = ''
    #self.logger.announce('Starting Domain Group Enum')

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password) #domain=self.domain
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net groups Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)  
                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle'] 

                self.logger.debug('Looking up reachable domain(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Domain Groups enumerated')
                self.logger.highlight("    {} Domain Group Accounts".format(tmpdomain))

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        resp = impacket.dcerpc.v5.samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                        if self.debug:
                            resp.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()

                    for group in resp['Buffer']['Buffer']:
                        gid = group['RelativeId']
                        r = impacket.dcerpc.v5.samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],impacket.dcerpc.v5.samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                        #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                        logging.debug('Dump of hSamrQueryInformationGroup response:')
                        if self.debug:
                            info.dump()

                        self.logger.highlight('{:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        groupLog += '{:<30}  membercount: {}\n'.format(group['Name'], info['Buffer']['General']['MemberCount'])


                        groupResp = impacket.dcerpc.v5.samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                        logging.debug('Dump of hSamrGetMembersInGroup response:')
                        if self.debug:
                            groupResp.dump()

                        for member in groupResp['Members']['Members']:
                            try:
                                m = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, member)
                                if self.debug:
                                    m.dump()
                                guser = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, m['UserHandle'], impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('     {}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                groupLog += '{}\\{:<30}  \n'.format(tmpdomain, guser['Buffer']['All']['UserName'])

                                if group['Name'] == 'Domain Admins':
                                    self.db.add_da(self.domain, guser['Buffer']['All']['UserName'])

                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()
                            except Exception as e: #failed function
                                logging.debug('failed a user lookup with error: {}'.format(str(e)))
                                self.logger.error('    Member with SID {} might be a group'.format(member.fields['Data']))
                                pass

                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['GroupHandle'])

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
        logging.debug('failed connect in group1.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in group1.a')
            pass
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

def users1(smb):
    """Enum domain users."""
    users = ''
    self = smb
    #self.logger.announce('Starting Domain Users Enum')
    if self.args.save:
        filename = "{}-users.txt".format(self.domain)
        savefile = open(filename,"w")

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password) #domain=self.domain
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('NetUsers Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)
                logging.debug('Dump of hSamrConnect response:')
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle']

                self.logger.debug('Looking up domain name(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:')
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                self.logger.debug('Looking up users in domain:' + domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Domain Users enumerated')
                self.logger.highlight("     {} Domain User Accounts".format(tmpdomain))

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        resp = impacket.dcerpc.v5.samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateUsersInDomain response:')
                        if self.debug:
                            resp.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    for user in resp['Buffer']['Buffer']:
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here:
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                        #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                        self.logger.highlight('{}\\{:<20}  rid: {}'.format(tmpdomain, user['Name'], user['RelativeId']))
                        users += '{}\\{:<20}  rid: {}\n'.format(tmpdomain, user['Name'], user['RelativeId'])

                        self.db.add_user(self.domain, user['Name'])

                        if self.args.save:
                            savefile.write("{}\n".format(user['Name']))

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'], impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])

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
        logging.debug('failed connect in users1.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in users1.a')
            pass
        return

    if self.args.save: 
        savefile.close()
        self.logger.success("Usernames saved to: {}".format(filename))

    try:
        dce.disconnect()
    except:
        logging.debug('Failed dce disconnect in users1')
        pass

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Users_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(users), log_name)
        self.logger.announce("Saved Domain Users output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Users Enum')
    return


def computers1(smb):
    """Enum Domain Computers.

    Prints output and adds them to cmxdb
    """
    comps = ''
    self = smb
    #self.logger.announce('Starting Domain Computers Enum')
    if self.args.save:
        filename = "{}-computers.txt".format(self.domain)
        savefile = open(filename,"w")

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password) #domain=self.domain
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('NetUsers Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)
                logging.debug('Dump of hSamrConnect response:')
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle']

                self.logger.debug('Looking up domain name(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:')
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                self.logger.debug('Looking up users in domain:' + domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:')
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        #need one for workstations and second gets the DomainControllers
                        respComps = impacket.dcerpc.v5.samr.hSamrEnumerateUsersInDomain(dce, domainHandle, impacket.dcerpc.v5.samr.USER_WORKSTATION_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                        respServs = impacket.dcerpc.v5.samr.hSamrEnumerateUsersInDomain(dce, domainHandle, impacket.dcerpc.v5.samr.USER_SERVER_TRUST_ACCOUNT, enumerationContext=enumerationContext)

                        logging.debug('Dump of hSamrEnumerateUsersInDomain Comps response:')
                        if self.debug:
                            respComps.dump()
                        logging.debug('Dump of hSamrEnumerateUsersInDomain Servs response:')
                        if self.debug:
                            respServs.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    self.logger.success('Domain Controllers enumerated')
                    self.logger.highlight("      {} Domain Controllers".format(tmpdomain))
                    comps += 'Domain Controllers  \n'

                    for user in respServs['Buffer']['Buffer']:
                        #servers
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here:
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                        self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                        comps += '{:<23} rid: {} \n'.format(user['Name'], user['RelativeId'])

                        #def add_computer(self, ip='', hostname='', domain=None, os='', dc='No'):
                        self.db.add_computer(hostname=user['Name'][:-1], domain=tmpdomain, dc='Yes')
                        if self.args.save:
                            savefile.write("{}\n".format(user['Name']))

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'],impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])


                    print('')
                    self.logger.success('Domain Computers enumerated')
                    self.logger.highlight("      {} Domain Computer Accounts".format(tmpdomain))
                    comps += '\nDomain Computers \n'


                    for user in respComps['Buffer']['Buffer']:
                        #workstations
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
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
                        if self.args.save:
                            savefile.write("{}\n".format(user['Name']))

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'],impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])


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
        logging.debug('failed connect in computers1.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in computers')
            pass
        return

    if self.args.save: 
        savefile.close()
        self.logger.success("Computers saved to: {}".format(filename))

    try:
        dce.disconnect()
    except:
        self.logging.error('Failed dce disconnect during computers')
        pass

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Computers_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(comps), log_name)
        self.logger.announce("Saved Domain Computers output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Computer Enum')
    return


def group2(smb):
    """Enum a target group in domain.

    Prints output and #adds them to cmxdb
    """
    self = smb
    targetGroup = self.args.group
    groupFound = False
    groupLog = ''

    if targetGroup == '':
        self.logger.error("Must specify a group name after --group ")
        return list()

    #self.logger.announce('Starting Domain Group Enum')

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password, domain=self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net groups Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)
                logging.debug('Dump of hSamrConnect response:')
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle']

                self.logger.debug('Looking up reachable domain(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:')
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                logging.debug('Looking up groups in domain: ' + domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:')
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        resp = impacket.dcerpc.v5.samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                        logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                        if self.debug:
                            resp.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    for group in resp['Buffer']['Buffer']:
                        gid = group['RelativeId']
                        r = impacket.dcerpc.v5.samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],impacket.dcerpc.v5.samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                        #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                        logging.debug('Dump of hSamrQueryInformationGroup response:')
                        if self.debug:
                            info.dump()

                        if group['Name'] == targetGroup:
                            self.logger.success('\"{}\" Domain Group Found in {}'.format(targetGroup, tmpdomain))
                            self.logger.highlight("    \"{}\" Group Info".format(targetGroup))
                            groupFound = True
                            self.logger.highlight('Member Count: {}'.format(info['Buffer']['General']['MemberCount']))

                            groupResp = impacket.dcerpc.v5.samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                            logging.debug('Dump of hSamrGetMembersInGroup response:')
                            if self.debug:
                                groupResp.dump()

                            for member in groupResp['Members']['Members']:
                                m = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, member)
                                guser = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, m['UserHandle'], impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                groupLog += '{}\\{:<30}  \n'.format(tmpdomain, guser['Buffer']['All']['UserName'])

                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()

                    if groupFound is False:
                        self.logger.error("Specified group was not found")
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['GroupHandle'])


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
        logging.debug('failed connect in group2.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in group2.a')
            pass
        return

    try:
        dce.disconnect()
    except:
        self.logging.error('Failed dce disconnect during groups')
        pass

    if self.args.logs and groupFound:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Members_of_{}_on_{}.log'.format(targetGroup, ctime)
        write_log(str(groupLog), log_name)
        self.logger.announce("Saved Group Members output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Group Enum')
    return


def find_da1(smb):
    """Enum Domain Computers.

    Prints output and adds them to cmxdb
    """
    comps = ''
    self = smb
    #self.logger.announce('Starting Domain Computers Enum')
    if self.args.save:
        filename = "{}-computers.txt".format(self.domain)
        savefile = open(filename,"w")

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password) #domain=self.domain
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('NetUsers Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)
                logging.debug('Dump of hSamrConnect response:')
                if self.debug:
                    resp.dump()
                serverHandle = resp['ServerHandle']

                self.logger.debug('Looking up domain name(s)')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:')
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']

                self.logger.debug('Looking up domain:' + domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                logging.debug('Dump of hSamrLookupDomainInSamServer response:')
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId = resp['DomainId'])
                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']

                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                while status == impacket.nt_errors.STATUS_MORE_ENTRIES:
                    try:
                        #need one for workstations and second gets the DomainControllers
                        respComps = impacket.dcerpc.v5.samr.hSamrEnumerateUsersInDomain(dce, domainHandle, impacket.dcerpc.v5.samr.USER_WORKSTATION_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                        respServs = impacket.dcerpc.v5.samr.hSamrEnumerateUsersInDomain(dce, domainHandle, impacket.dcerpc.v5.samr.USER_SERVER_TRUST_ACCOUNT, enumerationContext=enumerationContext)

                        logging.debug('Dump of hSamrEnumerateUsersInDomain Comps response:')
                        if self.debug:
                            respComps.dump()
                        logging.debug('Dump of hSamrEnumerateUsersInDomain Servs response:')
                        if self.debug:
                            respServs.dump()

                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise
                        resp = e.get_packet()


                    self.logger.success('Domain Controllers enumerated')
                    self.logger.highlight("      {} Domain Controllers".format(tmpdomain))
                    comps += 'Domain Controllers  \n'

                    for user in respServs['Buffer']['Buffer']:
                        #servers
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()

                        # r has the clases defined here:
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                        self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                        comps += '{:<23} rid: {} \n'.format(user['Name'], user['RelativeId'])

                        #def add_computer(self, ip='', hostname='', domain=None, os='', dc='No'):
                        self.db.add_computer(hostname=user['Name'][:-1], domain=tmpdomain, dc='Yes')
                        if self.args.save:
                            savefile.write("{}\n".format(user['Name']))

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'],impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])


                    print('')
                    self.logger.success('Domain Computers enumerated')
                    self.logger.highlight("      {} Domain Computer Accounts".format(tmpdomain))
                    comps += '\nDomain Computers \n'


                    for user in respComps['Buffer']['Buffer']:
                        #workstations
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
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
                        if self.args.save:
                            savefile.write("{}\n".format(user['Name']))

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'],impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])


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
        logging.debug('failed connect in computers1.a {}'.format(str(e)))
        self.logger.error('Failed to identify the domain controller for {} Can you ping it?'.format(self.domain))
        self.logger.error('    Try adding the switch -dc ip.ad.dr.es  with a known DC')
        self.logger.error('    or ensure your /etc/resolv.conf file includes target DC(s)')
        try:
            dce.disconnect()
        except:
            logging.debug('failed disconnect in computers')
            pass
        return

    if self.args.save: 
        savefile.close()
        self.logger.success("Computers saved to: {}".format(filename))

    try:
        dce.disconnect()
    except:
        self.logging.error('Failed dce disconnect during computers')
        pass

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Domain_Computers_of_{}_on_{}.log'.format(tmpdomain, ctime)
        write_log(str(comps), log_name)
        self.logger.announce("Saved Domain Computers output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Domain Computer Enum')
    return


