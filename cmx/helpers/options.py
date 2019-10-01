#!/usr/bin/env python3

####################################################################
#   options.py   -   Hold any possible value a function may require.
#   
#   Trying this as a way to limit number of passed args to any function.
#   Ideally, we wont have to remember all the possible values needed to be passed in
#
#   Whenever a new option or param is needed it can be added here and not in each of the exec methods/classes etc..
#   Each class will then instantiate an options object and set the values it needs.
#
#
# Classes:
#   options
#
# Non-Class Functions:
#   -
#
####################################################################


class options():

	def init(args):
	#strings
    	self.username = None
    	self.password = None
    	self.hash = None
    	self.lmhash = ''
    	self.nthash = ''
	
    	self.domain = None              # Domain name ~ ie. OCEAN
    	self.domain_dns = None			# FQDN of domain ~ ie. ocean.depth
    	self.host = None         		# Can be a hostname or an IP
    	self.hostname = None     		# For hostname
	
    	self.server_os = None           # Full host os string i.e. ~ Windows 6.1 Build 7601
    	self.server_os_minor = None		# using above example would be 1
    	self.server_os_major = None		# using above example would be 6
    	self.server_os_build = None		# using above example would be 7601
	
    	self.bootkey = None
    	self.output_filename = None
    	self.smbv = None
    	self.smb_share_name = None
    	self.dc_ip = None
    	self.domain_dns = None
    	self.exec_method = None
    	self.local_ip = None


	#ints
    	self.smbv = None
    	self.os_arch = None             # 32 or 64
    	self.threads = args.threads
    	self.timeout = args.timeout
    	self.verbosity = args.verbose


	#Bools
    	self.signing = False
    	self.ntlmv2 = False
    	self.nullLogin = False
    	self.admin_privs = False
	
    	self.debug = args.debug


 	#Objects
    	self.logger = None				# CMXLogAdapter()
    	self.remote_ops = None        	# RemoteOperations()
    	self.connection = None			# protocol connection object - XXXConnection() 
	
    	self.dialect = None				# dialects map to connection object dialect values 
        								#     self.conn.getDialect()