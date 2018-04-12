#!/usr/bin/env python3

# (c) 2018 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>
# and Sebastiaan Groot <sebastiaang _monkeytail_ kpn-cert.nl> (for his
# EIQ lib)

# This software is GPLv3 licensed, except where otherwise indicated

import sys
import json
import xml
import re
import optparse
import requests
import urllib3
import time
import eiqcalls
import eiqjson
import pprint

from config import settings


def transform(feedJSON, feedID, options):
    '''
    Take the EIQ JSON objects, extract all observables into lists,
    and transform those into the selected ruletypes.
    '''
    if options.verbose:
        print("U) Converting EIQ JSON objects into a rules group ...")
    entities = []
    for entity in feedJSON:
        if 'extracts' in entity:
            if 'description' in entity['data']:
                description = entity['data']['description']
            if 'meta' in entity:
                meta = entity['meta']
                tlp = 'AMBER'
                if 'tlp_color' in meta:
                    tlp = meta['tlp_color']
                if 'title' in meta:
                    title = meta['title']
                if entity['extracts']:
                    entry = {title: {
                        'actor-id': [],
                        'description': [description],
                        'domain': [],
                        'email': [],
                        'email-subject': [],
                        'file': [],
                        'ipv4': [],
                        'ipv6': [],
                        'hash-md5': [],
                        'hash-sha1': [],
                        'hash-sha256': [],
                        'hash-sha512': [],
                        'snort': [],
                        'tlp': [tlp],
                        'uri': [],
                        'yara': []
                    }}
                    for extract in entity['extracts']:
                        classification = ''
                        if 'kind' and 'value' in extract:
                            kind, value = extract['kind'], extract['value']
                        if 'meta' in extract:
                            meta = extract['meta']
                            if 'classification' in meta:
                                classification = meta['classification']
                        if classification == 'bad' or \
                           kind == 'snort' or \
                           kind == 'yara':
                            if kind in entry[title]:
                                entry[title][kind].append(value)
                    entities.append(entry)
    return entities


def cleanup(text=None):
    if text:
        text = text.replace('text: ', ' | ')
        text = re.sub(r'<[^>]*?>', '', text)
    return text


def rulegen(entities, options):
    ruleset = []
    if options.type == 's':
        if options.verbose:
            print("U) Building Snort/SourceFire rules ...")
        sid = int(options.sid)
        for entity in entities:
            for title in entity:
                actor = entity[title]['actor-id']
                if not actor:
                    actor = ['unknown']
                tlp = entity[title]['tlp']
                description = cleanup(options.name + " | " + title)
                message = "TLP:" + ''.join(tlp) + \
                          " | Actor: " + ''.join(actor) + \
                          " | " + ''.join(description)
                message.replace('"', '')
            for kind in entity[title]:
                for value in entity[title][kind]:
                    if kind == 'ipv4':
                        ruleset.append('alert ip $HOME_NET any -> ' +
                                       value + ' any ' +
                                       '(msg:"' + message + '"; ' +
                                       'flow:to_server,established; ' +
                                       'gid:1; ' +
                                       'priority:1; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if kind == 'ipv6':
                        ruleset.append('alert ip $HOME_NET any -> ' +
                                       value + ' any ' +
                                       '(msg:"' + message + '"; ' +
                                       'flow:to_server,established; ' +
                                       'gid:1; ' +
                                       'priority:1; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if kind == 'file':
                        ruleset.append('alert tcp $HOME_NET any -> ' +
                                       options.dest + ' any ' +
                                       '(msg:"' + message + '"; ' +
                                       'flow:to_server,established; ' +
                                       'content:"' + value + '"; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if 'hash-' in kind:
                        type = kind.split('-')[1]
                        if type == 'md5' or \
                           type == 'sha256' or \
                           type == 'sha512':
                            ruleset.append('alert tcp $HOME_NET any -> ' +
                                           options.dest + ' any ' +
                                           '(msg:"' + message + '"; ' +
                                           'hash:' + type + "; "
                                           'protected_content:"' + value +
                                           '"; ' +
                                           'sid:' + str(sid) + '; ' +
                                           'rev:1;' +
                                           ')')
                            sid += 1
                    if kind == 'uri':
                        ruleset.append('alert tcp $HOME_NET any -> ' +
                                       options.dest + ' $HTTP_PORTS ' +
                                       '(msg:"' + message + '"; ' +
                                       'flow:to_server,established; ' +
                                       'content:"' + value + '"; ' +
                                       'http_uri; ' +
                                       'service:http; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if kind == 'domain':
                        domainparts = value.split('.')
                        content = ''
                        for part in domainparts:
                            content += '|' + hex(len(part))[2:].zfill(2) + \
                                       '|' + part
                        content += '|00|'
                        ruleset.append('alert udp $HOME_NET any -> ' +
                                       options.dest + ' 53 ' +
                                       '(msg:"' + message + '"; ' +
                                       'byte_test:1,!&,0xF8,2; ' +
                                       'content:"' + content + '"; ' +
                                       'fast_pattern:only; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                        ruleset.append('alert tcp $HOME_NET any -> ' +
                                       options.dest + ' 53 ' +
                                       '(msg:"' + message + '"; ' +
                                       'byte_test:1,!&,0xF8,2; ' +
                                       'content:"' + content + '"; ' +
                                       'fast_pattern:only; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if kind == 'email' or kind == 'email-subject':
                        ruleset.append('alert tcp $HOME_NET any -> ' +
                                       options.dest + ' $SMTP_PORTS ' +
                                       '(msg:"' + message + '"; ' +
                                       'content:"' + value + '"; ' +
                                       'sid:' + str(sid) + '; ' +
                                       'rev:1;' +
                                       ')')
                        sid += 1
                    if kind == 'snort':
                        ruleset.append(value)
    if options.verbose:
        print("U) Ruleset is: ")
        print(("\n".join(ruleset)))
    return ruleset


def download(feedID, options):
    '''
    Download the given feed number from the EclecticIQ JSON instance
    '''
    if not settings.EIQSSLVERIFY:
        if options.verbose:
            print("W) You have disabled SSL verification for EIQ, " +
                  "this is not recommended.")
    eiqAPI = eiqcalls.EIQApi(insecure=not(settings.EIQSSLVERIFY))
    eiqHost = settings.EIQHOST + settings.EIQVERSION
    eiqFeed = settings.EIQFEEDS + '/' + str(feedID)
    eiqAPI.set_host(eiqHost)
    eiqAPI.set_credentials(settings.EIQUSER, settings.EIQPASS)
    eiqToken = eiqAPI.do_auth()
    eiqHeaders = {}
    eiqHeaders['Authorization'] = 'Bearer %s' % (eiqToken['token'],)
    try:
        if options.verbose:
            print("U) Contacting " + eiqHost + eiqFeed + ' ...')
        response = eiqAPI.do_call(endpt=eiqFeed,
                                  headers=eiqHeaders,
                                  method='GET')
    except:
        raise
        print("E) An error occurred contacting the EIQ URL at " +
              feedURL)
    if not response or ('errors' in response):
        if response:
            for err in response['errors']:
                print('[error %d] %s' % (err['status'], err['title']))
                print('\t%s' % (err['detail'], ))
        else:
            print('unable to get a response from host')
            sys.exit(1)
    if 'content_blocks' not in response['data']:
        if options.verbose:
            print("E) No content blocks in feed ID!")
    else:
        if options.verbose:
            print("U) Attempting to download latest feed content ...")
        content_block = response['data']['content_blocks'][0]
        content_block = content_block.replace(settings.EIQVERSION, "")
        response = eiqAPI.do_call(endpt=content_block,
                                  headers=eiqHeaders,
                                  method='GET')
        if options.verbose:
            pprint.pprint(response)
        if 'entities' not in response:
            print("E) No entities in response!")
        else:
            return response['entities']


def process(ruleset, options):
    timestamp = time.strftime('%Y%m%d-%H%M%S-')
    if options.action == 'mail' or options.action == 'm':
        pass
    if options.action == 'file' or options.action == 'f':
        try:
            if not options.simulate:
                if options.verbose:
                    print("U) Writing ruleset to file: " +
                          timestamp + settings.OUTPUTFILE)
                with open(timestamp + settings.OUTPUTFILE, 'w') as file:
                    file.writelines(('\n'.join(ruleset)+'\n'))
            else:
                print("U) Not writing anything to disk, as " +
                      "simulation option was set!")
        except:
            print("E) An error occurred writing to disk!")


if __name__ == "__main__":
    cli = optparse.OptionParser(usage="usage: %prog [-v | -t | -s " +
                                      "| -n | -d | -a] <EIQ feed ID>")
    cli.add_option('-v', '--verbose',
                   dest='verbose',
                   action='store_true',
                   default=False,
                   help='[optional] Enable progress/error info (default: ' +
                        'disabled)')
    cli.add_option('-t', '--type',
                   dest='type',
                   default='s',
                   help='[optional] Set the type of IDS / SIEM rule you ' +
                        'wish to create: [s]ourcefire/Snort (default). ')
    cli.add_option('-d', '--dest',
                   dest='dest',
                   default='any',
                   help='[optional] Set the destination network name you ' +
                        'want to create the ruleset for (default: \'any\')')
    cli.add_option('-s', '--simulate',
                   dest='simulate',
                   action='store_true',
                   default=False,
                   help='[optional] Do not actually generate anything, ' +
                        'just simulate everything. Mostly useful with ' +
                        'the -v/--verbose flag for debugging purposes.')
    cli.add_option('-i', '--sid',
                   dest='sid',
                   default=1000000,
                   help='[optional] Specify the rule id to start counting ' +
                        'from. Particularly important when creating Snort ' +
                        'SourceFire rulesets (default: 1000000)')
    cli.add_option('-n', '--name',
                   dest='name',
                   default=settings.COMMENT,
                   help='[optional] Override the default comment from ' +
                        'the configuration file (default: COMMENT field ' +
                        'from the settings.py file)')
    cli.add_option('-a', '--action',
                   dest='action',
                   default=settings.ACTION,
                   help='Specify the action to take with the generated ' +
                        'ruleset: [f]ile, [m]ail (default: write to ' +
                        'the [f]ilename specified in settings.py')
    (options, args) = cli.parse_args()
    if len(args) < 1:
        cli.print_help()
        sys.exit(1)
    if len(args) > 1:
        print("E) Please specify exactly a feedID from EclecticIQ.")
        sys.exit(1)
    else:
        try:
            feedID = int(args[0])
        except:
            print("E) Please specify a numeric feedID only.")
            sys.exit(1)
        feedDict = download(feedID, options)
        entities = transform(feedDict, feedID, options)
        ruleset = rulegen(entities, options)
        if ruleset:
            process(ruleset, options)
