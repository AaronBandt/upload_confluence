#!/usr/bin/python

import sys
import logging
import argparse
import ConfigParser
import requests
from requests.auth import HTTPBasicAuth
import json

# requests is chatty
logging.getLogger("requests").setLevel(logging.WARNING)
requests.packages.urllib3.disable_warnings()
log = logging.getLogger(__name__)


def http_query(mode, args):
    """
    Manipulate data on an http endpoint
    """

    auth = HTTPBasicAuth(args.username, args.password)

    if mode ==  'get':
        r = requests.get(args.url, verify=args.ssl_verify, headers=args.headers, auth=auth, params=args.data)
    elif mode ==  'post':
        if args.attach_file:
            log.info('Uploading attachment...')
            data = {'comment' : args.attach_comment}
            r = requests.post(args.url, verify=args.ssl_verify, headers=args.headers, auth=auth, files=args.my_file, data=data)
            if r.status_code == requests.codes.ok:
                log.info('Success.')
        else:
            r = requests.post(args.url, verify=args.ssl_verify, headers=args.headers, auth=auth, json=args.data)
    elif mode ==  'put':
        r = requests.put(args.url, verify=args.ssl_verify, headers=args.headers, auth=auth, json=args.data)
    else:
        log.error('invalid http mode.')

    if r.status_code == requests.codes.ok:
        return r.json()
    else:
        try:
            response = r.json()
            log.warn('{0}'.format(response['message']))
        except:
            msg = 'There was an error querying confluence: http_status_code=%s,reason=%s,request=%s' % (r.status_code, r.reason, args.url)
            log.error('{0}'.format(msg))
            raise Exception(msg)


def _parse_args():
    """
    Parse all the command line arguments.
    """

    help="""
    Manipulate confluence via the REST API.

    >>> upload_confluence.py -H localhost -P 8090 -s ~/conf/upload_confluence.ini -k TST -t 'My new page' -f ~/page_cotnents.txt -a ~/test.png
    Updating page
    Page updated successfully: http://localhost:8090/display/TST/My+new+page
    Checking for existing attachment
    found existing attachment:  att950293
    Uploading attachment...
    """

    mp = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                 description=help)
    mp.add_argument('-H',
                    '--host',
                    dest='host_fqdn',
                    help='[REQUIRED] FQDN of the confluence server.',
                    default=None)
    mp.add_argument('-P',
                    '--port',
                    dest='host_port',
                    help='Port number of the confluence server.',
                    default='80')
    mp.add_argument('-t',
                    '--title',
                    dest='page_title',
                    help='[REQUIRED] The name of the page you wish to create/update.',
                    default=None)
    mp.add_argument('-k',
                    '--key',
                    dest='space_key',
                    help='[REQUIRED] The space key the page lives in.',
                    default=None)
    mp.add_argument('-f',
                    '--file',
                    dest='content_file',
                    help='Path to file containing the content you wish to upload.',
                    default=None)
    mp.add_argument('-a',
                    '--attach',
                    dest='attach_file',
                    help='Path to file you wish to attach to the page.',
                    default=None)
    mp.add_argument('-c',
                    '--comment',
                    dest='attach_comment',
                    help='Comment to add to the attachment.',
                    default=None)
    mp.add_argument('-m',
                    '--markup',
                    dest='markup_type',
                    help='The type of markup in the file. Choices are wiki (default) or storage.',
                    default='wiki')
    mp.add_argument('-s',
                    '--secrets',
                    dest='secrets_config_file',
                    help='Secret config file to use.',
                    default=None)
    mp.add_argument('-S',
                    '--ssl',
                    dest='ssl_verify',
                    help='Whether or not the server is using ssl. Can be True, False, or path to ca cert',
                    default=None)
    mp.add_argument('-d',
                    '--debug',
                    action='store_true',
                    help='Enable debugging.')

    return mp.parse_args()


def get_page(args): 
    """
    Retrieve information about a page in confluence so we can update.
    """

    setattr(args, 'data', {'title': args.page_title, 'spaceKey': args.space_key, 'expand': 'version'})

    response = http_query('get', args)

    # FIXME: Should have some checking here for more than one response.
    if response['results']:
        page_id = response['results'][0]['id']
        page_version = response['results'][0]['version']['number']
        if args.debug:
            log.debug('{0}'.format(json.dumps(response, indent=4, sort_keys=True)))
    else:
        page_id = None
        page_version = None

    return page_id, page_version


def create_page(args):
    """
    Retrieve information about a page in confluence so we can update.
    """

    log.info('Creating new page')

    setattr(args, 'data', {'type': 'page',
                           'title': args.page_title,
                           'space': {'key': args.space_key},
                           'body': {'storage':
                                       {'value': args.page_content,
                                        'representation': args.markup_type
                                       }
                                   }
                           })

    response = http_query('post', args)

    if args.debug:
        log.debug('{0}'.format(json.dumps(response, indent=4, sort_keys=True)))

    log.info('Page created successfully: {0}{1}'.format(args.url_base, response['_links']['webui']))


def update_page(args):
    """
    Retrieve information about a page in confluence so we can update.
    """

    log.info('Updating page...')

    setattr(args, 'data', {'id': args.page_id,
                           'type':'page',
                           'title': args.page_title,
                           'space':{'key': args.space_key},
                           'body':{'storage':
                                      {'value': args.page_content,
                                       'representation': args.markup_type
                                      }
                                  },
                           'version':{'number': args.page_version + 1}})

    setattr(args, 'url', '{0}/{1}'.format(args.url_api_content, args.page_id))

    response = http_query('put', args)

    if args.debug:
        log.debug('{0}'.format(json.dumps(response, indent=4, sort_keys=True)))

    log.info('Page updated successfully: {0}{1}'.format(args.url_base, response['_links']['webui']))


def attach_file(args):
    """
    Attach a file to a page. If an attachment of the same name exists, it
    will update it.
    """

    setattr(args, 'url', '{0}/{1}/child/attachment'.format(args.url_api_content, args.page_id))
    setattr(args, 'my_file', {'file': open(args.attach_file, 'rb')})

    # Have to check to see if the attachment already exists.
    log.info('Checking for existing attachment...')
    r =  http_query('get', args)
    if r['results']:
        for a in r['results']:
            if a['title'] == args.attach_file.rsplit('/', 1)[1]:
                attachment_id = a['id']
                log.info('Found existing attachment: {0}'.format(attachment_id))
                setattr(args, 'url', '{0}/{1}/child/attachment/{2}/data'.format(args.url_api_content, args.page_id, attachment_id))

    http_query('post', args)
    

def main():

    # parse the args
    args = _parse_args()

    log_level = getattr(logging, 'DEBUG') if args.debug else getattr(logging, 'INFO')

    root = logging.getLogger()
    root.setLevel(log_level)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    formatter = logging.Formatter('%(levelname)-8s- %(message)s')
    console.setFormatter(formatter)
    root.addHandler(console)

    # Make sure we have required args
    required = ['host_fqdn',
                'space_key',
                'page_title']
    for r in required:
        if not args.__dict__[r]:
            log.error('Required option is missing: {0}'.format(r))
            sys.exit(2)

    # Parse the config
    secrets_config = ConfigParser.ConfigParser()
    secrets_config.read(args.secrets_config_file)
    setattr(args, 'username', secrets_config.get('auth', 'username'))
    setattr(args, 'password', secrets_config.get('auth', 'password'))

    # Have to do this becasue it can be a boolean or a string (path to a ca file)
    if args.ssl_verify == 'True':
        args.ssl_verify = bool(args.ssl_verify)
    if args.ssl_verify == 'False':
        args.ssl_verify = False

    # Validate the port based on the required protocol
    if args.ssl_verify:
        protocol = "https"
        # Unspecified port will be 80 by default, not correct if ssl is ON
        if (args.host_port == '80'):
            args.host_port = '443'
    else:
        protocol = "http"

    setattr(args, 'headers', {'Content-Type': 'application/json'})
    setattr(args, 'url_base', '{0}://{1}:{2}'.format(protocol, args.host_fqdn, args.host_port))
    setattr(args, 'url_api_content', '{0}/rest/api/content'.format(args.url_base))
    setattr(args, 'url', args.url_api_content)

    # Get the page info
    page_id, page_version = get_page(args)

    setattr(args, 'page_id', page_id)
    setattr(args, 'page_version', page_version)

    if args.content_file:
        with open (args.content_file, "r") as content:
             setattr(args, 'page_content', content.read())

    if page_id:
        update_page(args)
    else:
        create_page(args)

    if args.attach_file:
        setattr(args, 'headers', {'X-Atlassian-Token': 'no-check'})
        attach_file(args)

if __name__ == '__main__':
    main()
