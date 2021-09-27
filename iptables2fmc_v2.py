import requests
import base64
import json
import xmltodict

# FMC settings (Test LAB)
host = "10.48.26.176:40443"
username = "apiscript"
password = "Cisco!123"
autodeploy = False
timeout=300

def encodeBasicAuth(username, password):
    '''Encoded basic authentication into username:password format in base64.'''
    return base64.b64encode(f'{username}:{password}'.encode('ascii')).decode('utf-8')

def getTokens():
    '''Returns auth tokens (access and refresh) as well as DomainUUID.'''

    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
    payload={}

    headers = {
        'Authorization': f'Basic {encodeBasicAuth(username, password)}'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    return {'X-auth-access-token': response.headers['X-auth-access-token'], 'X-auth-refresh-token': response.headers['X-auth-refresh-token'], 'DOMAIN_UUID': response.headers['DOMAIN_UUID']}

def getDeviceRecords(authAccessToken, authRefreshToken, domainUUID):
    url = f"https://{host}/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords"

    payload={}
    headers = {
        'X-auth-access-token': authAccessToken,
        'X-auth-refresh-token': authRefreshToken,
        'Authorization': f'Basic {encodeBasicAuth(username, password)}'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    print(response.text)

def createACP(authAccessToken, authRefreshToken, domainUUID, type, name, description, defaultAction):
    url = f"https://{host}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies"
    payload = {
        "type": type,
        "name": name,
        "description": description,
        "defaultAction": {
            "action": defaultAction
        }
    }

    headers = {
        'X-auth-access-token': authAccessToken,
        'X-auth-refresh-token': authRefreshToken,
        'Authorization': f'Basic {encodeBasicAuth(username, password)}'
    }

    response = requests.request("POST", url, headers=headers, json=payload, verify=False)
    return json.loads(response.text)['id']

def xml2json():
    '''Converts iptables xml into a dictionary and saves it as a json file.'''
    with open("iptables_xml.txt") as f:
        input = xmltodict.parse(f.read())
        rules_as_dict = json.loads(json.dumps(input))

    # save json to a file -> this is a little bit inefficient as it could've been done above
    with open("iptables_json.txt", "w") as out:
        json.dump(rules_as_dict, out, indent=2) 

    return rules_as_dict

def parseRule(rule):
    if 'conditions' in rule.keys():

        # -- MATCH --
        if 'match' in rule['conditions'].keys():
            # Source
            if 's' in rule['conditions']['match'].keys():
                print('Source: ', rule['conditions']['match']['s'])
                
            # Destination
            if 'd' in rule['conditions']['match'].keys():
                print('Destination: ', rule['conditions']['match']['d'])
    
            # Protocol
            if 'p' in rule['conditions']['match'].keys():
                print('Protocol: ', rule['conditions']['match']['p'])

            # Src. Port
            if 'sport' in rule['conditions']['match'].keys():
                print('Src. Port: ', rule['conditions']['match']['sport'])

            # Dest. Port
            if 'dport' in rule['conditions']['match'].keys():
                print('Dest. Port: ', rule['conditions']['match']['dport'])

        # SET
        if 'set' in rule['conditions'].keys():
            # if there's multiple sets
            if isinstance(rule['conditions']['set'], list):
                for set in rule['conditions']['set']:
                    if 'match-set' in set.keys():
                        # some are bugged so check if there's a #text tag under match-set

                        if isinstance(set['match-set'], dict):
                            print('Set: ', set['match-set']['#text'])
                        else:
                            print('Set: ', set['match-set'])

                        
                    # Source
                    if 's' in set.keys():
                        print('Source: ', set['s'])

                    # Destination
                    if 'd' in set.keys():
                        print('Destination: ', set['s'])

                    # Protocol
                    if 'p' in set.keys():
                        print('Protocol: ', set['p'])
            else:
                 if 'match-set' in rule['conditions']['set'].keys():
                    # some are bugged so check if there's a #text tag under match-set

                    if isinstance(rule['conditions']['set']['match-set'], dict):
                        print('Set: ', rule['conditions']['set']['match-set']['#text'])
                    else:
                        print('Set: ', rule['conditions']['set']['match-set'])
                        
                    # Source
                    if 's' in rule['conditions']['set'].keys():
                        print('Source: ', rule['conditions']['set']['s'])

                    # Destination
                    if 'd' in rule['conditions']['set'].keys():
                        print('Destination: ', rule['conditions']['set']['d'])

                    # Protocol
                    if 'p' in rule['conditions']['set'].keys():
                        print('Protocol: ', rule['conditions']['set']['p'])
        # MULTIPORT
        if 'multiport' in rule['conditions']:

            # Protocol
            if 'p' in rule['conditions']['multiport']:
                print('Protocol: ', rule['conditions']['multiport']['p'])

            # Dest. Ports 
            if 'dports' in rule['conditions']['multiport']:
                print('Dest. ports: ', rule['conditions']['multiport']['dports'])


        # COMMENT
        if 'comment' in rule['conditions']:
            print('Comment: ', rule['conditions']['comment']['comment'])

    # -- ACTIONS --
    if rule['actions']:
        # accept / allow
        if 'ACCEPT' in rule['actions']:
            print('Action: Allow')
        # drop / block
        if 'DROP' in rule['actions']:
            print('Action: Block')

if __name__ == "__main__":
    #tokens = getTokens()
    #getDeviceRecords(tokens['X-auth-access-token'], tokens['X-auth-refresh-token'], tokens['DOMAIN_UUID'])
    #containerUUID = createACP(tokens['X-auth-access-token'], tokens['X-auth-refresh-token'], tokens['DOMAIN_UUID'], "AccessPolicy", f"ACP_{str(int(time.time()))}", "Sample API-created ACP", "BLOCK")


    rules = xml2json()
    forwardRules = rules['iptables-rules']['table'][2]['chain'][1]['rule'] # tip: use https://jsonformatter.org/json-viewer to easily explore the json file
    forwardRules_list = []
    for rule in forwardRules: # last index: 2475 (DROP)
        forwardRules_list.append(rule)
        print('Parsing ', rule)
        parseRule(rule)
        print('----------- \n')


# to-do list:
# - try to replicate the rule json by getting it from the FMC