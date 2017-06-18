#!/usr/bin/env python
"""
Allows the user to make outbound API requests.  This file can either be used as
an import'able python library or as a command line application callable by
anything.
"""

#Copyright 2017 William Stearns <william.l.stearns@gmail.com>
#Released under the GNU GPL version 3.

#Dedicated to Annie, Lucy, Ricky, Rogue, and Stone, 5 of the .... 'apiest cats you'll ever meet.

from __future__ import print_function		#To make print require parens
import sys
import json
import base64
import subprocess				#Used to execute command line openssl binary for a particular signature
#import urllib					#To handle URL quoting (not used at the moment)
import uuid
import netrc					#To load username/password or api key pairs from .netrc
import urlparse
import hmac					#Needed?
import hashlib					#Needed?
#from OpenSSL import SSL			#If not available, "sudo port install py-openssl" or "sudo pip install pyopenssl"
from calendar import timegm
from datetime import datetime
import requests					#Actually makes the API calls
from requests.auth import HTTPBasicAuth		#If not available:  sudo -H pip install requests
from requests.auth import AuthBase
from requests_aws4auth import AWS4Auth		#If not available:  sudo -H pip install requests-aws4auth ( https://github.com/sam-washington/requests-aws4auth/ )


apicat_version = "0.14"

apicat_verbose = False				#Can change to True with "-v" command line param.


api_vendor = {
		'amazon-ec2': {'auth': 'amazon-aws4', 'urltop': 'https://ec2.amazonaws.com'},
		'amazon-s3': {'auth': 'amazon-aws4', 'urltop': 'https://s3.amazonaws.com'},
		'atlanticnet': {'auth': 'atlanticnet-sha256', 'urltop': 'https://cloudapi.atlantic.net'},
		'cloudbank': {'auth': 'amazon-session-token', 'urltop': 'https://api.execute-api.us-east-1.amazonaws.com/prod/v1'},
		'cloudpassage': {'auth': 'bearer-token-cloudpassage', 'urltop': 'https://api.cloudpassage.com/v1'},
		'digitalocean': {'auth': 'bearer-token', 'urltop': 'https://api.digitalocean.com/v2'},
		'digitalocean-basic': {'auth': 'basic', 'urltop': 'https://api.digitalocean.com/v2'},
		'github': {'auth': 'basic', 'urltop': 'https://api.github.com'},
		'ipinfo': {'auth': None, 'urltop': 'https://ipinfo.io'},
		'jsonplaceholder': {'auth': None, 'urltop': 'https://jsonplaceholder.typicode.com'},
		'rackspace-dfw': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://dfw.servers.api.rackspacecloud.com/v2'},
		'rackspace-hkg': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://hkg.servers.api.rackspacecloud.com/v2'},
		'rackspace-iad': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://iad.servers.api.rackspacecloud.com/v2'},
		'rackspace-lon': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://lon.servers.api.rackspacecloud.com/v2'},
		'rackspace-ord': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://ord.servers.api.rackspacecloud.com/v2'},
		'rackspace-syd': {'auth': 'rackspace-x-auth-token', 'urltop': 'https://syd.servers.api.rackspacecloud.com/v2'},
		'virustotal': {'auth': 'apikey-params', 'urltop': 'https://www.virustotal.com/vtapi/v2'}
	     }

api_vendor_in_progress = {
				'google': {'urltop': 'https://www.googleapis.com/compute/v1'}
			 }



class CloudpassageAuth(AuthBase):
	"""Attaches HTTP Cloudpassage Authentication to the given Request object."""
	def __init__(self, sessionkey):
		# setup any auth-related data here
		self.sessionkey = sessionkey

	def __call__(self, r):
		# modify and return the request
		r.headers['Authorization'] = self.sessionkey
		return r



class RackspaceAuth(AuthBase):
	"""Attaches HTTP Rackspace Authentication to the given Request object."""
	def __init__(self, sessionkey):
		# setup any auth-related data here
		self.sessionkey = sessionkey

	def __call__(self, r):
		# modify and return the request
		r.headers['X-Auth-Token'] = self.sessionkey
		return r



class AmazonPoolAuth(AuthBase):
	"""Attaches HTTP Amazon Pool Authentication to the given Request object."""
	def __init__(self, sessionkey):
		# setup any auth-related data here
		self.sessionkey = sessionkey

	def __call__(self, r):
		# modify and return the request
		r.headers['Authorization'] = self.sessionkey
		return r



def utc_timestamp():
	"""Returns seconds since the epoch in UTC/GMT."""
	#Equivalent of shell date '+%s'
	return timegm(datetime.utcnow().utctimetuple())



def debug(debug_string):
	"""Provide ability to debug, sends message to stderr and optionally an SNS prod-debug queue."""

	global apicat_verbose

	if apicat_verbose:
		sys.stderr.write(str(debug_string) + '\n')
		#return push_to_sns('prod-debug', debug_string)



def generic_api(auth_object, headers, top_url, endpoint, params, user_method, payload, files):
	#FIXME - change all returns to send back (return_text_or_json, status_code) tuple
	#FIXME - recognize and handle atlantic.net error codes
	"""Actually make the API call."""

	method = str(user_method).upper()

	if str(endpoint).lstrip('/') == '':
		full_url = str(top_url).rstrip('/')
	else:
		full_url = str(top_url).rstrip('/') + '/' + str(endpoint).lstrip('/')

	#Multiple files not currently working
	#files_array = []
	#if files is not None and files != '':
	#	for one_file in files:
	#		files_array.append(('files', (one_file, open(one_file, 'rb'))))

	#Try to get one file working; isn't at the moment, we get 'Invalid submission format, POST request contains no file field...'
	files_array = None
	if files is not None and files != '':
		files_array = {'file': (files, open(files, 'rb'))}

	debug("request_method:" + method)
	debug("request_headers:" + str(headers))
	debug("request_auth:" + str(auth_object))
	debug("request_payload:" + str(payload))
	debug("request_files:" + str(files_array))

	if method in ('PUT', 'POST'):
		if files_array is None or files_array == []:
			if auth_object is None:
				#debug("1")
				r = requests.request(method, full_url, headers=headers, data=payload, params=params)
			else:
				#debug("2")
				r = requests.request(method, full_url, auth=auth_object, headers=headers, data=payload, params=params)
		else:			#Files is set, so we remove data=payload
			if auth_object is None:
				#debug("3")
				r = requests.request(method, full_url, headers=headers, params=params, files=files_array)
			else:
				#debug("4")
				r = requests.request(method, full_url, auth=auth_object, headers=headers, params=params, files=files_array)
	elif method in ('GET', 'DELETE', 'HEAD', 'PATCH', 'OPTIONS'):
		if auth_object is None:
			r = requests.request(method, full_url, headers=headers, params=params)
		else:
			r = requests.request(method, full_url, auth=auth_object, headers=headers, params=params)
	else:
		debug("error_unhandled_method_requested:" + str(user_method))
		return ''

	debug("request_url:" + r.url)
	debug("request headers as sent:" + str(r.request.headers))
	debug("request_encoding:" + str(r.encoding))
	debug("response_status_code:" + str(r.status_code))
	debug("response_headers:" + str(r.headers))

	if r.status_code in (204, 205):
		#204 No content (Just fine, seen with DELETE's)
		return ''
	elif str(r.status_code).startswith(('2', '3')):
		#201 created (Successfull post)
		try:
			return json.dumps(r.json())
		except:
			return ''
	else:
		#400 Bad request (possibly json provided on stdin is malformed?)
		#401 Unauthorized (wrong username/password combination?  Need to supply 2 factor authentication?)
		#403 Forbidden (maybe this user/key does not have permissions to perform this action?)
		#404 Not found (this object is (no longer?) there; double delete?)
		if not apicat_verbose:			#Don't write twice
			sys.stderr.write("response_status_code:" + str(r.status_code) + "\n")
		sys.stderr.write("error_text_response:" + str(r.text).replace('\n', ' ').replace('\r', '') + "\n")
		return ''



#def amazon_signature(secret_key, b64_obj):
#	"""Generate signature for Amazon AWS."""
#
#	#return base64.b64encode(hmac.new(secret_key, b64_obj, hashlib.sha1).digest()
#	return hmac.new(secret_key, b64_obj.encode('utf-8'), hashlib.sha256).digest()


#def amazon_get_signature_key(secret_key, date_stamp, region, service_name):
#	"""Amazon version 4 signing process, with thanks to http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html . """
#	kDate = amazon_signature(('AWS4' + secret_key).encode('utf-8'), date_stamp)
#	kRegion = amazon_signature(kDate, region)
#	kService = amazon_signature(kRegion, service_name)
#	kSigning = amazon_signature(kService, 'aws4_reguest')
#	return kSigning


def amazon_pool_authenticate_user(username, password, pool_id, app_client_id):
	import boto3
	client = boto3.client('cognito-idp')

	auth_params = {'USERNAME' : username, 'PASSWORD' : password}

	init_response = client.admin_initiate_auth(AuthFlow='ADMIN_NO_SRP_AUTH', \
						    ClientId=app_client_id, \
						    AuthParameters=auth_params, \
						    UserPoolId=pool_id \
						  )

	#FIXME - remember if we're interactive or not before doing the following challenge handling.
	while 'ChallengeName' in init_response:
		if init_response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
			while True:
				new_password = raw_input('Temporary password must be updated, enter new password: : ')
				new_password_repeated = raw_input('Re-enter new password: : ')
				if new_password == new_password_repeated:
					break
				else:
					print('Passwords do not match\n')

			challenge_response = {'NEW_PASSWORD' : new_password, 'USERNAME' : username}
			init_response = client.admin_respond_to_auth_challenge(UserPoolId=pool_id, \
									   ClientId=app_client_id, \
									   ChallengeName='NEW_PASSWORD_REQUIRED', \
									   ChallengeResponses=challenge_response, \
									   Session=init_response['Session'] \
									   )
		elif init_response['ChallengeName'] == 'SMS_MFA':
			code = raw_input('Enter MFA code: ')
			challenge_response = {'USERNAME': username, 'SMS_MFA_CODE' : code}
			init_response = client.admin_respond_to_auth_challenge(UserPoolId=pool_id, \
									   ClientId=app_client_id, \
									   ChallengeName='SMS_MFA', \
									   ChallengeResponses=challenge_response, \
									   Session=init_response['Session'] \
									   )
		else:
			debug('unhandled response')
			debug(init_response)


	debug('Successful Authentication!')
	debug('Session Token:')
	return init_response['AuthenticationResult']['IdToken']


def cloudpassage_session_key(username, password):
	"""Returns the session key needed to authenticate to CloudPassage."""
	if username != '' and password != '':
		debug("request_cloudpassage_username_and_password_both_have_values")
	elif username == '' and password == '':
		debug("error_request_cloudpassage_username_and_password_both_blank")
	else:
		debug("error_request_cloudpassage_username_and_password_one_blank")
	session_headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + str(base64.b64encode(str(username) + ":" + str(password)))}
	#debug(str({'Authorization': 'Basic ' + str(base64.b64encode(str(username) + ":" + str(password)))}))
	#session_json = generic_api(None, session_headers, 'https://api.cloudpassage.com', 'oauth/access_token?grant_type=client_credentials', {}, 'POST', None)


	session_request = requests.request('POST', 'https://api.cloudpassage.com/oauth/access_token', headers=session_headers, params={'grant_type': 'client_credentials'})
	#debug("session_url:" + str(session_request.url))
	session_json = session_request.json()

	#debug("request_cloudpassage_session_json:" + str(session_json))
	session_token = session_json['access_token']
	#debug("request_cloudpassage_session_token:" + str(session_token))
	#debug("\n")
	return session_token



def rackspace_session_key(username, password):
	"""Generate a session key to use for rackspace api calls."""
	if username != '' and password != '':
		debug("request_rackspace_username_and_password_both_have_values")
	elif username == '' and password == '':
		debug("error_request_rackspace_username_and_password_both_blank")
	else:
		debug("error_request_rackspace_username_and_password_one_blank")
	session_headers = {'Content-Type': 'application/json'}

	#Careful - the API is _very_ sensitive to changes in this payload string.
	session_payload = '{"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":"' + str(username) + '", "apiKey":"' + str(password) + '"}}}'
	session_request = requests.request('POST', 'https://identity.api.rackspacecloud.com/v2.0/tokens', headers=session_headers, data=session_payload)
	session_json = session_request.json()

	if session_json.has_key('access'):
		session_token = session_json['access']['token']['id']
	elif session_json.has_key('badRequest'):
		sys.stderr.write("error_session_text_response:" + str(session_request.text).replace('\n', ' ').replace('\r', '') + "\n")
		session_token = ''
	else:
		sys.stderr.write("error_session_text_response:" + str(session_request.text).replace('\n', ' ').replace('\r', '') + "\n")
		session_token = ''

	return session_token



def apihost_wrapper(given_api_name, auth_dict, endpoint, method, payload, params, prov_details, files):
	"""Handles any apihost specific details of constructing the request or managing the results."""

	region = prov_details['region']

	api_name = str(given_api_name).lower()

	api_hostname = urlparse.urlparse(api_vendor[api_name]['urltop']).hostname

	if not auth_dict.has_key('username'):
		auth_dict['username'] = None

	#For the calls where we're using basic auth, the requests module will correctly go down to netrc and fetch this itself.
	#However, we still need to populate auth_dict['username'] and auth_dict['password'] for the calls where we're building an auth header.
	if auth_dict['username'] is None or auth_dict['username'] == '':
		netrc_dict = None
		try:
			netrc_handle = netrc.netrc()
			netrc_dict = netrc_handle.hosts
		except:
			sys.stderr.write("Unable to read netrc file.\n")

		if netrc_dict is not None:
			debug("request_hostname_for_netrc:" + api_hostname)
			if netrc_dict.has_key(api_hostname):
				auth_dict['username'] = netrc_dict[api_hostname][0]
				auth_dict['password'] = netrc_dict[api_hostname][2]
				#debug("request_username_for_netrc:" + str(auth_dict['username']))
				#debug("request_password_for_netrc:" + str(auth_dict['password']))


	auth_object = None
	headers = {'Content-Type': 'application/json'}

	if api_name in api_vendor:

		if api_name.startswith('rackspace-'):
			headers['Accept'] = 'application/json'

		if api_vendor[api_name].has_key('auth'):
			if api_vendor[api_name]['auth'] == 'amazon-aws4':
				if region is None or region == '':
					region = 'us-east-1'

				if auth_dict['username'] is not None and auth_dict['password'] is not None:
					service = api_hostname.split('.')[0]

					auth_object = AWS4Auth(auth_dict['username'], auth_dict['password'], region, service)

					#t = datetime.utcnow()			#Not needed at the moment.
					#amzdate = t.strftime('%Y%m%dT%H%M%SZ')
					#amzdate = t.strftime('%a, %d %b %Y %H:%M:%S GMT')
					#amzdate = t.isoformat()		#This appears to be the best choice, not needed at the moment.

					#datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

					#canonical_uri = '/'
					#canonical_querystring = ''

					params['AWSAccessKeyId'] = auth_dict['username']
					params['Action'] = endpoint
					endpoint = ''
					#params['Version'] = '2013-10-15'

					##We have to use a tuple to preserve ordering in request parameters for Amazon
					#new_params = list()

					#for one_param_key in sorted(params):
					#	new_params.append((one_param_key, params[one_param_key]))
					#	#if canonical_querystring != '':
					#	#	canonical_querystring = canonical_querystring + '&'
					#	#canonical_querystring = canonical_querystring + str(one_param_key) + "=" + str(params[one_param_key])

					#params = tuple(new_params)

					#debug("Amazon sorted parameters:" + str(params))
					#debug("canonical_querystring:" + canonical_querystring)

					#canonical_headers = 'host:' + api_hostname + '\n' + 'x-amz-date:' + amzdate + '\n'
					#signed_headers = 'host;x-amz-date'
					#payload_hash = hashlib.sha256(payload).hexdigest()
					#canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

					#algorithm = 'AWS4-HMAC-SHA256'
					#credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
					#string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()

					#signing_key = amazon_get_signature_key(auth_dict['password'], datestamp, region, service)

					#signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

					#authorization_header = algorithm + ' ' + 'Credential=' + auth_dict['username'] + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

					#headers['x-amz-date'] = amzdate
					headers['host'] = api_hostname
					#headers['Authorization'] = authorization_header

					#raw_policy = '{"expiration": "2009-01-01T00:00:00Z", "conditions": [ {"bucket": "s3-bucket"}, ["starts-with", "$key", "uploads/"], {"acl": "private"}, {"success_action_redirect": "http://localhost/"}, ["starts-with", "$Content-Type", ""], ["content-length-range", 0, 1048576] ] }'
					#params['policy'] = base64.b64encode(raw_policy)
					#params['signature'] = amazon_signature(auth_dict['password'], params['policy'])
				else:
					debug("error_request_amazon_authentication_no_key_or_secret")
			elif api_vendor[api_name]['auth'] == 'basic':
				if auth_dict['username'] is not None:
					auth_object = HTTPBasicAuth(auth_dict['username'], auth_dict['password'])
			elif api_vendor[api_name]['auth'] == 'apikey-params':
				if auth_dict['password'] is not None:
					params['apikey'] = auth_dict['password']
			elif api_vendor[api_name]['auth'] == 'bearer-token':
				headers['Authorization'] = 'Bearer ' + str(auth_dict['username'])
			elif api_vendor[api_name]['auth'] == 'amazon-session-token':
				#headers['Authorization'] = amazon_pool_authenticate_user(auth_dict['username'], auth_dict['password'], prov_details['pool'], prov_details['app_client'])
				#The above line doesn't work: It appears to be the same problem of the requests module assuming no authentication was done and replacing it with Basic Auth.  We override with the same approach of overriding the base class; see AmazonPoolAuth.
				session_token = amazon_pool_authenticate_user(auth_dict['username'], auth_dict['password'], prov_details['pool'], prov_details['app_client'])
				auth_object = AmazonPoolAuth(str(session_token))	#The session_token does NOT need to be preceded by Bearer
			elif api_vendor[api_name]['auth'] == 'atlanticnet-sha256':
				params['ACSAccessKeyId'] = auth_dict['username']
				params['Action'] = endpoint
				endpoint = ''						#Atlantic puts the endpoint as a param: ...&Action=list-instances&...
				params['Format'] = 'json'
				params['Rndguid'] = str(uuid.uuid4())
				params['Timestamp'] = utc_timestamp()
				params['Version'] = '2010-12-30'

				string_to_sign = str(params['Timestamp']) + str(params['Rndguid'])
				# Create a hash of the signature using sha256 and then base64 encode the sha256 hash:
				#We don't need to use: urllib.quote(    ,'')[:-3] because requests will url-encode the signature when converting all params into a URL.
				#The following command is very sensitive to change.
				signature_output = subprocess.check_output("/bin/echo -n " + str(string_to_sign) + " | openssl dgst -sha256 -hmac " + str(auth_dict['password']) + " -binary | openssl enc -base64", shell=True).rstrip("\n")
				params['Signature'] = signature_output
			elif api_vendor[api_name]['auth'] == 'bearer-token-cloudpassage':
				session_token = cloudpassage_session_key(auth_dict['username'], auth_dict['password'])

				#Problem - any entry with username and password in .netrc overrides the following attempt at an Authorization header and the API call fails...
				#headers['Authorization'] = 'Bearer ' + str(session_token)
				#...; fix is to use a custom authorizer object as follows.
				auth_object = CloudpassageAuth('Bearer ' + str(session_token))
			elif api_vendor[api_name]['auth'] == 'rackspace-x-auth-token':
				session_token = rackspace_session_key(auth_dict['username'], auth_dict['password'])

				#Problem - any entry with username and password in .netrc overrides the following attempt at an Authorization header and the API call fails...
				#headers['Authorization'] = 'Bearer ' + str(session_token)
				#...; fix is to use a custom authorizer object as follows.
				auth_object = RackspaceAuth(str(session_token))



			#Note; no explicit test for auth type is None as there's no action to take in this case.

		return generic_api(auth_object, headers, api_vendor[api_name]['urltop'], endpoint, params, method, payload, files)
	else:
		debug("error_unknown_vendor:" + api_name + " .  Will attempt to use https://api." + api_name + ".com/")
		return generic_api(auth_object, headers, "https://api." + api_name + ".com/", endpoint, params, method, payload, files)



if __name__ == "__main__":
	import argparse

	provider_list = ", ".join(api_vendor.keys())

	parser = argparse.ArgumentParser(description='apicat version ' + str(apicat_version) + ' makes API calls to any of the following providers: ' + provider_list + '.')
	parser.add_argument('-m', '--method', help='Which API method (GET, PUT, POST, DELETE)  to use', default='GET', required=False)
	parser.add_argument('-v', '--verbose', help='Be verbose', action='store_true', required=False)
	parser.add_argument('-a', '--apihost', help='Which apihost to use', default='jsonplaceholder', required=False)
	parser.add_argument('-e', '--endpoint', help='Which endpoint to use', required=False)
	parser.add_argument('-u', '--username', help='Username (or digitalocean token)', required=False)
	parser.add_argument('-p', '--password', help='Password', required=False)
	parser.add_argument('--params', help='Parameters', type=json.loads, default={}, required=False)
	parser.add_argument('--region', help='Region', required=False)
	parser.add_argument('--files', help='Files', required=False)
	parser.add_argument('--pool', help='pool_id for amazon cognito', required=False)
	parser.add_argument('--appclient', help='app_client_id for amazon cognito', required=False)



	#import ConfigParser

	#config = ConfigParser.ConfigParser()
	#config.read('cognito.cfg')

	#pool_id = config.get('auth', 'pool_id')
	#app_client_id = config.get('auth', 'app_client_id')





	#Not yet needed
	#parser.add_argument('-k', '--key', help='Key', required=False)
	#parser.add_argument('-s', '--secret', help='Secret', required=False)

	args = vars(parser.parse_args())

	auth_info = {}

	if args['username'] is not None and args['username'] != '':
		auth_info['username'] = args['username']
	else:
		auth_info['username'] = None

	if args['password'] is not None and args['password'] != '':
		auth_info['password'] = args['password']
	else:
		auth_info['password'] = None

	#Not yet needed
	#if args['key'] is not None and args['key'] != '':
	#	auth_info['key'] = args['key']
	#else:
	#	auth_info['key'] = None

	#if args['secret'] is not None and args['secret'] != '':
	#	auth_info['secret'] = args['secret']
	#else:
	#	auth_info['secret'] = None

	if auth_info['username'] is None and auth_info['password'] is None: 		#and auth_info['key'] == None and auth_info['secret'] == None:
		debug("authentication:No authentication supplied, will use .netrc file if authentication needed.")

	payload = ''
	if not args['method'].upper() in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH', 'OPTIONS'):
		debug("error_invalid_method:" + str(args['method'].upper()))
	elif args['method'].upper() in ('PUT', 'POST'):
		if args['files'] is None or args['files'] == '':
			debug("request_payload:Reading payload from stdin")
			payload = sys.stdin.read()

	if args['verbose']:
		apicat_verbose = True

	print(apihost_wrapper(args['apihost'], auth_info, args['endpoint'], str(args['method']).upper(), payload, args['params'], {'region': args['region'], 'pool': args['pool'], 'app_client': args['appclient']}, args['files']))

	#FIXME - come up with an appropriate shell return code
