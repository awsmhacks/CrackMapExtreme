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

from cmx.helpers.misc import *
from cmx.connection import *
from cmx.protocols.smb.MISC.smbspider import *
import impacket
from datetime import datetime
import time
import cmx
from cmx.helpers.logger import highlight, write_log
from cmx import config as cfg
import ntpath


def disks1(smb):
    """Enumerate disks.

    *** This does require local admin i think. Made to return nothing if not admin.

    """
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    try:
        #self.logger.info('Attempting to enum disks...')
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('disks Binding start')
            dce.bind(impacket.dcerpc.v5.srvs.MSRPC_UUID_SRVS)
            try:
                logging.debug('Get disks via hNetrServerDiskEnum...')
                #self.logger.announce('Attempting to enum disks...')
                resp = impacket.dcerpc.v5.srvs.hNetrServerDiskEnum(dce, 0)
                self.logger.success('Disks enumerated on {} !'.format(self.host))

                for disk in resp['DiskInfoStruct']['Buffer']:
                    if disk['Disk'] != '\x00':
                        #self.logger.results('Disk: {} found on {}'.format(disk['Disk'], self.host))
                        self.logger.highlight("Found Disk: {}\\ ".format(disk['Disk']))
                        enumlog += "Found Disk: {}\\  \n".format(disk['Disk'])

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


    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Disks_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved Disks output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.info('Finished disk enum')
    dce.disconnect()
    return


def sessions1(smb):
    """Enumerate sessions.

    Identifes sessions and their originating host.
    Using impackets hNetrSessionEnum from https://github.com/SecureAuthCorp/impacket/blob/ec9d119d102251d13e2f9b4ff25966220f4005e9/impacket/dcerpc/v5/srvs.py
    """
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    try:
        #self.logger.announce('Starting Session Enum')
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('netsessions Binding start')
            dce.bind(impacket.dcerpc.v5.srvs.MSRPC_UUID_SRVS)
            try:
                logging.debug('Get netsessions via hNetrSessionEnum...')
                resp = impacket.dcerpc.v5.srvs.hNetrSessionEnum(dce, '\x00', '\x00', 10)  #no clue why \x00 is used for client and username?? but it works!

                for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                    userName = session['sesi10_username'][:-1]
                    sourceIP = session['sesi10_cname'][:-1][2:]
                    #self.logger.results('User: {} has session originating from {}'.format(userName, sourceIP))
                    self.logger.highlight("{} has session originating from {} on {}".format(userName, sourceIP, self.host,))
                    enumlog += "{} has session originating from {} on {}  \n".format(userName, sourceIP, self.host,)

                self.logger.success('Sessions enumerated on {} !'.format(self.host))
            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Sessions, win10 may require LocalAdmin')
                dce.disconnect()
                return
        except Exception as e: #failed bind
            logging.debug('failed bind {}'.format(str(e)))
            self.logger.error('Failed to enum Sessions, win10 may require LocalAdmin')
            dce.disconnect()
            return
    except Exception as e: #failed connect
        logging.debug('failed connect {}'.format(str(e)))
        self.logger.error('Failed to enum Sessions, win10 may require LocalAdmin')
        dce.disconnect()
        return

    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Sessions_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Sessions output saved to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Session Enum')
    dce.disconnect()
    return


def loggedon1(smb):
    """Enumerate Loggedon users.

    I think it requires localadmin, but handles if it doesnt work.
    """
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    try:
        #self.logger.announce('Checking for logged on users')
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\wkssvc', smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('loggedon Binding start')
            dce.bind(impacket.dcerpc.v5.wkst.MSRPC_UUID_WKST)
            try:
                logging.debug('Get loggedonUsers via hNetrWkstaUserEnum...')
                #self.logger.announce('Attempting to enum loggedon users...')
                resp = impacket.dcerpc.v5.wkst.hNetrWkstaUserEnum(dce, 1)   # theres a version that takes 0, not sure the difference?
                self.logger.success('Loggedon-Users enumerated on {} !'.format(self.host))

                for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                    wkst_username = wksta_user['wkui1_username'][:-1] # These are defined in https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/wkst.py#WKSTA_USER_INFO_1
                    #self.logger.results('User:{} is currently logged on {}'.format(wkst_username,self.host))
                    self.logger.highlight("{} is currently logged on {} ({})".format(wkst_username, self.host, self.hostname))
                    enumlog += "{} is currently logged on {} ({})  \n".format(wkst_username, self.host, self.hostname)

            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to enum Loggedon Users, win10 may require localadmin?')
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
        log_name = 'Loggedon-Users_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved Loggedon-Users output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished checking for logged on users')
    dce.disconnect()
    return


def local_users1(smb):
    """Enumerate local users.

    Need to figure out if needs localadmin or its a waste of effort
    """
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    try:
        #self.logger.announce('Checking Local Users')
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()

        try:
            logging.debug('net local users Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)

            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)

                logging.debug('Dump of hSamrConnect response:')
                if self.debug:
                    resp.dump()

                self.logger.debug('Looking up host name')
                serverHandle = resp['ServerHandle']
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:')
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                logging.debug('Looking up localusers on: '+ domains[0]['Name'])
                resp = impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

                logging.debug('Dump of hSamrLookupDomainInSamServer response:')
                if self.debug:
                    resp.dump()

                resp = impacket.dcerpc.v5.samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])

                logging.debug('Dump of hSamrOpenDomain response:')
                if self.debug:
                    resp.dump()

                domainHandle = resp['DomainHandle']
                status = impacket.nt_errors.STATUS_MORE_ENTRIES
                enumerationContext = 0

                self.logger.success('Local Users enumerated on {} !'.format(self.host))
                self.logger.highlight("   Local User Accounts")

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
                        #users
                        r = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, user['RelativeId'])
                        logging.debug('Dump of hSamrOpenUser response:')
                        if self.debug:
                            r.dump()
                        # r has the clases defined here: 
                            #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                        #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                        self.logger.highlight("{}\\{:<15} :{} ".format(self.hostname, user['Name'], user['RelativeId']))

                        self.db.add_user(self.hostname, user['Name'])
                        enumlog += "{}\\{:<15} :{}  \n".format(self.hostname, user['Name'], user['RelativeId'])

                        info = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, r['UserHandle'],impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                        logging.debug('Dump of hSamrQueryInformationUser2 response:')
                        if self.debug:
                            info.dump()
                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['UserHandle'])
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


    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Local-Users_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved Local Users output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Checking Local Users')
    dce.disconnect()
    return


def local_groups1(smb):
    """Enumerate local groups.

    Need to figure out if needs localadmin or its a waste of effort
    """
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    try:
        #self.logger.announce('Checking Local Groups')
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        try:
            logging.debug('Get net localgroups Binding start')
            dce.bind(impacket.dcerpc.v5.samr.MSRPC_UUID_SAMR)
            try:
                logging.debug('Connect w/ hSamrConnect...')
                resp = impacket.dcerpc.v5.samr.hSamrConnect(dce)  

                logging.debug('Dump of hSamrConnect response:') 
                if self.debug:
                    resp.dump()

                serverHandle = resp['ServerHandle'] 
                self.logger.debug('Checking host name')
                resp2 = impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)

                logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                if self.debug:
                    resp2.dump()

                domains = resp2['Buffer']['Buffer']
                tmpdomain = domains[0]['Name']
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
                self.logger.success('Local Groups enumerated on: {}'.format(self.host))
                self.logger.highlight("        Local Group Accounts")

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
                        self.logger.highlight('Group: {:<20}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                        enumlog += 'Group: {:<20}  membercount: {} \n'.format(group['Name'], info['Buffer']['General']['MemberCount'])

                        groupResp = impacket.dcerpc.v5.samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                        logging.debug('Dump of hSamrGetMembersInGroup response:')
                        if self.debug:
                            groupResp.dump()

                        for member in groupResp['Members']['Members']:
                            m = impacket.dcerpc.v5.samr.hSamrOpenUser(dce, domainHandle, impacket.dcerpc.v5.samr.MAXIMUM_ALLOWED, member)
                            guser = impacket.dcerpc.v5.samr.hSamrQueryInformationUser2(dce, m['UserHandle'], impacket.dcerpc.v5.samr.USER_INFORMATION_CLASS.UserAllInformation)
                            self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                            enumlog += '{}\\{:<30}  \n'.format(tmpdomain, guser['Buffer']['All']['UserName'])

                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                guser.dump()

                        impacket.dcerpc.v5.samr.hSamrCloseHandle(dce, r['GroupHandle'])
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


    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Local-Groups_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved Local Groups output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Checking Local Groups')
    dce.disconnect()
    return


def rid_brute1(smb, maxrid=None):
    """Brute force RIDs."""
    self = smb
    enumlog = ''
    enumlog += 'Executed as {} \n'.format(self.username)

    logging.debug('Starting RID Brute')

    if not maxrid:
        maxrid = int(self.args.rid_brute)

    try:
        rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\lsarpc', username=self.username, password=self.password, smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()

        dce.connect()
        try:
            logging.debug('Brute forcing RIDs')
            dce.bind(impacket.dcerpc.v5.lsat.MSRPC_UUID_LSAT)
            try:
                logging.debug('Open w/ hLsarOpenPolicy2...')
                resp = impacket.dcerpc.v5.lsad.hLsarOpenPolicy2(dce, impacket.dcerpc.v5.dtypes.MAXIMUM_ALLOWED | impacket.dcerpc.v5.lsat.POLICY_LOOKUP_NAMES)
                policyHandle = resp['PolicyHandle']

                if self.debug:
                    logging.debug('Dump of hLsarOpenPolicy2 response:')
                    resp.dump()

                resp = impacket.dcerpc.v5.lsad.hLsarQueryInformationPolicy2(dce, policyHandle, impacket.dcerpc.v5.lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
                domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

                if self.debug:
                    logging.debug('Dump of hLsarQueryInformationPolicy2 response:')
                    resp.dump()

                soFar = 0
                SIMULTANEOUS = 1000
                self.logger.success("RID's enumerated on: {}".format(self.host))
                self.logger.highlight("         RID Information")


                for j in range(maxrid // SIMULTANEOUS + 1):
                    if (maxrid - soFar) // SIMULTANEOUS == 0:
                        sidsToCheck = (maxrid - soFar) % SIMULTANEOUS
                    else:
                        sidsToCheck = SIMULTANEOUS

                    if sidsToCheck == 0:
                        break

                    sids = list()

                    for i in range(soFar, soFar + sidsToCheck):
                        sids.append(domainSid + '-%d' % i)
                    try:
                        #if self.debug:    # this is huge/gross, even for debug
                        #    logging.debug('Dump of hLsarLookupSids response:')
                        #    resp.dump()
                        resp = impacket.dcerpc.v5.lsat.hLsarLookupSids(dce, policyHandle, sids, impacket.dcerpc.v5.lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)

                    except Exception as e:
                        if str(e).find('STATUS_NONE_MAPPED') >= 0:
                            soFar += SIMULTANEOUS
                            continue
                        elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                            resp = e.get_packet()
                        else:
                            raise

                    for n, item in enumerate(resp['TranslatedNames']['Names']):
                        if item['Use'] != impacket.dcerpc.v5.samr.SID_NAME_USE.SidTypeUnknown:
                            rid    = soFar + n
                            domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                            user   = item['Name']
                            sid_type = impacket.dcerpc.v5.samr.SID_NAME_USE.enumItems(item['Use']).name
                            self.logger.highlight("{}\\{:<15} :{} ({})".format(domain, user, rid, sid_type))
                            enumlog += "{}\\{:<15} :{} ({}) \n".format(domain, user, rid, sid_type)


                    soFar += SIMULTANEOUS


            except Exception as e: #failed function
                logging.debug('failed function {}'.format(str(e)))
                self.logger.error('Failed to Brute force RIDs, are you localadmin?')
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
        log_name = 'RID-Brute_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved RID Brute output to {}/{}".format(cfg.LOGS_PATH,log_name))

    dce.disconnect()

    logging.debug('Finished RID brute')
    return


def spider1(smb, share=None, folder='.', pattern=[], regex=[], exclude_dirs=[], depth=None, content=False, onlyfiles=True, onlydir=False):
    """Spider a share.

    Args:

    Raises:

    Returns:

    """
    self = smb

    logging.debug('Starting Spider')
    spider = SMBSpider(self.conn, self.logger)

    logging.debug('Start Spidering')
    start_time = time.time()
    if not share:
        spider.spider(self.args.spider, self.args.spider_folder, self.args.pattern,
                      self.args.regex, self.args.exclude_dirs, self.args.depth,
                      self.args.content, self.args.only_files, self.args.only_dir)
    else:
        spider.spider(share, folder, pattern, regex, exclude_dirs, self.args.depth, content, onlyfiles, onlydir)

    seconds = time.time() - start_time
    mins, seconds = divmod(seconds, 60)
    hrs, mins = divmod(mins, 60)

    self.logger.success("Done spidering (Completed in %02d hours, %02d minutes, %02d seconds)"%(hrs,mins,seconds))
    self.logger.success('Total Directories: {}'.format(spider.dircount))
    self.logger.success('Total Files: {}'.format(spider.filecount))

    return spider.results


def shares1(smb):
    """Enum accessable shares and privileges.

    OpSec Warning, this attempts to create a randomly named folder on each enumerated share
        to check for WRITE access.
    """
    self = smb
    temp_dir = ntpath.normpath("\\" + gen_random_string())
    permissions = []
    #self.logger.announce('Starting Share Enumeration')
    enumlog = ''

    try:
        for share in self.conn.listShares():
            share_name = share['shi1_netname'][:-1]
            share_remark = share['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark, 'access': []}
            read = False
            write = False

            try:
                self.conn.listPath(share_name, '\\')
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
        enumlog += 'Executed as {} \n'.format(self.username)
        enumlog += '{:<15} {:<15} {} \n'.format('Share', 'Permissions', 'Remark')
        enumlog += '{:<15} {:<15} {} \n'.format('-----', '-----------', '------')
        for share in permissions:
            name   = share['name']
            remark = share['remark']
            perms  = share['access']

            self.logger.highlight('{:<15} {:<15} {}'.format(name, ','.join(perms), remark))
            enumlog += '{:<15} {:<15} {} \n'.format(name, ','.join(perms), remark)

    except Exception as e:
        self.logger.error('Error enumerating shares: {}'.format(e))


    if self.args.logs:
        ctime = datetime.now().strftime("%b.%d.%y_at_%H%M")
        log_name = 'Shares_of_{}_on_{}.log'.format(self.host, ctime)
        write_log(str(enumlog), log_name)
        self.logger.announce("Saved Shares output to {}/{}".format(cfg.LOGS_PATH,log_name))

    #self.logger.announce('Finished Share Enumeration')
    return permissions

