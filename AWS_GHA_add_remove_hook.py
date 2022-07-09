import json
import urllib.request
import os
import array
import re

# read environment variables
APIKEY = os.environ["APIKEY"]
OKTAHOST = os.environ["OKTAHOST"]
ATTRIBUTE = os.environ["GHAATTRIBUTE"]
OKTAAUTHHEADER = os.environ["OKTAAUTHHEADER"]
OKTAAUTHHEADERVALUE = os.environ["OKTAAUTHHEADERVALUE"]

#
# SUBROUTINES
#

# read user record and the GHA roles attribute from Okta
def read_roles_for_user(userID):
    request = urllib.request.Request(OKTAHOST + '/api/v1/users/' + userID)
    request.add_header('Accept', '*/*');
    request.add_header('Authorization', 'SSWS ' + APIKEY);
    res = urllib.request.urlopen(request)
    data = res.read()
    userJSON = json.loads(data.decode('utf-8'))
    # Read roles attribute
    GHAroles = userJSON['profile'][ATTRIBUTE]
    return GHAroles
    
# get all groups from user
def read_groups_for_user(userID):
    request = urllib.request.Request(OKTAHOST + '/api/v1/users/' + userID + "/groups")
    request.add_header('Accept', '*/*');
    request.add_header('Authorization', 'SSWS ' + APIKEY);
    res = urllib.request.urlopen(request)
    data = res.read()
    groupJSON = json.loads(data.decode('utf-8'))
    return groupJSON

# delete specific entries
def delete_entries_from_attribute(groupName, userID):
    # read roles
    GHAroles = read_roles_for_user(userID)    
    
    # if user was removed from a role (R_xx) group then delete all *-groupname from GHAroles attribute
    if groupName.startswith("R_"):
        regex = re.compile(rf'\w*-{groupName}$')
        filteredRoles = [i for i in GHAroles if not regex.match(i)]
    # ifif user was removed from a property (P_YYY) group then delete all YYY-* from GHAroles attribute
    elif groupName.startswith("P_"):
        prop = re.search("^P_(\w+)$", groupName)
        regex = re.compile(rf'{prop.group(1)}-\w*')
        filteredRoles = [i for i in GHAroles if not regex.match(i)]
    return (filteredRoles)

# add entries to role attribute
def add_entries_to_attribute(groupName, userID):
    properties = []
    roles = []
    filteredRoles = []
    roleAttributeArray = []
    
    # read attribute in to add new groups
    roleAttributeArray = read_roles_for_user(userID)
    
    # read groups and parse P_ and R_ groups only. Add them into roles and properties list
    groupJSON = read_groups_for_user(userID)
    for group in groupJSON:
        if group["profile"]["name"].startswith("P_"):
            properties.append(group["profile"]["name"])
        if group["profile"]["name"].startswith("R_"):
            roles.append(group["profile"]["name"])

    # get all the P_ groups matching P_{2lettercode}.* if user was added to a role group
    if groupName.startswith("R_"):
        twoLetterPropertyCode = groupName[2:4]
        regex = re.compile(rf'P_{twoLetterPropertyCode}\w+')
        filteredPropertyGroups = [i for i in properties if regex.match(i)]
        for property in filteredPropertyGroups:
            roleAttributeArray.append(property[2:] + "-" + groupName)        
    # get all the R_ groups matching R_{2lettercode}_* if user was added to a property group
    elif groupName.startswith("P_"):
        fullPropertyCode = groupName[2:]
        twoLetterPropertyCode = groupName[2:4]
        regex = re.compile(rf'R_{twoLetterPropertyCode}_\w+')
        filteredRoleGroups = [i for i in roles if regex.match(i)]
        for role in filteredRoleGroups:
            roleAttributeArray.append(fullPropertyCode + "-" + role)
    
    return (roleAttributeArray)

# POST attribute to Okta
def post_attribute_to_okta (filteredRoles, userID):
    newRolesJSON = {
        "profile" : 
            {f"{ATTRIBUTE}" : 
                filteredRoles}
    }
    
    data = json.dumps(newRolesJSON)
    data = data.encode()
    
    request = urllib.request.Request(OKTAHOST + '/api/v1/users/' + userID, data)
    request.add_header('Authorization', 'SSWS ' + APIKEY);
    request.add_header('Accept', '*/*')
    request.add_header('Content-Type', 'application/json')
    res = urllib.request.urlopen(request)
    return (res.getcode())

def lambda_handler(event, context):
    # Okta Hook verifier for initial installation
    if "headers" in event:
        if "x-okta-verification-challenge" in event["headers"]:
            verifier = {"verification" : event["headers"]["x-okta-verification-challenge"]}
            return {
                'statusCode': 200,
                'body': json.dumps(verifier)
            }
        
        # Okta auth for subsequent invocation
        if "x-okta-auth" not in event["headers"]:
            authFail = {"AuthFailed" : "Header missing"}
            return {
                'statusCode': 503,
                'body': json.dumps(event["headers"])
            }
        else:
            if event["headers"]["x-okta-auth"] != "abcdefg":
                authFail = {"AuthFailed" : "Wrong verifier"}
                return {
                    'statusCode': 503,
                    'body': json.dumps(authFail)
                }

    # read parameters from Event
    body = json.loads(event["body"])
    type = body["data"]["events"][0]["eventType"]
    userID = body["data"]["events"][0]["target"][0]["id"]
    groupID = body["data"]["events"][0]["target"][1]["id"]
    groupName = body["data"]["events"][0]["target"][1]["displayName"]
    result = body["data"]["events"][0]["outcome"]["result"]

    # only continue if group add / remove succeeeded in the event sent
    if result == "SUCCESS" and (groupName.startswith("P_") or groupName.startswith("R_")):
        if type == "group.user_membership.remove":
            filteredRoles = delete_entries_from_attribute(groupName, userID)
        elif type == "group.user_membership.add":
            filteredRoles = add_entries_to_attribute(groupName, userID)
        
        statusPOST = post_attribute_to_okta (filteredRoles, userID)
        return {
            'statusCode': 200,
            'body': json.dumps(statusPOST)
        }               
    
