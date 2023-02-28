from ciscoconfparse import CiscoConfParse
import re
import socket
import struct
import requests
import json

objects = []
net_groups = []
services = []
svc_groups = []

has_obj_nat = []

used_objects = []
unused_objects = []
used_obj_groups = []
unused_obj_groups = []
used_services = []
unused_services = []
used_svc_groups = []
unused_svc_groups = []


def to_cidr(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def to_netmask(cidr):
    host_bits = 32 - int(cidr)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return str(netmask)

def appendIfAbsent(obj,list):
    if list.count(obj) > 0:
        pass
    else:
        list.append(obj)
    return

def find_port(result):
    if "eq" in result:
        port = result[result.find('eq')+3:].rstrip()
        return port
    else:
        print("PORT NOT EQUAL", result)
        return
    return

def find_objects():

    with open('../show_run.txt') as file:
        for line in file:

            parse = CiscoConfParse("../show_run.txt")

            acls = parse.find_objects(r"^access-list .* extended (permit|deny)")
            for acl in acls:

                ip_addrs = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(acl))
                new_ips = []

                for idx, ip in enumerate(ip_addrs):
                    if "255" in ip:
                        mask = to_cidr(ip)
                        new_ips[idx-1]["mask"] = str(mask)
                        new_ips[idx-1]["name"] = new_ips[idx-1]["name"]+"_"+str(mask)
                        pass
                    else:
                        obj = {
                            "name" : ip,
                            "ipv4" : ip,
                            "mask" : "32"
                        }

                    new_ips.append(obj)

                for ip in new_ips:
                    appendIfAbsent(ip,objects)                

            if line[:14] == 'object network':
                nextLine = next(file, '').rstrip()

                if nextLine[:8] == ' subnet ':

                    mask_start = nextLine.find('255')

                    name = line[14:].strip()
                    ipv4 = nextLine[8:mask_start-1]
                    mask = to_cidr(nextLine[mask_start:])

                    obj = {"name": name, "ipv4": ipv4, "mask" : str(mask)}

                    appendIfAbsent(obj,objects)

                elif nextLine[:6] == ' host ':

                    name = line[14:].strip()
                    ipv4 = nextLine[6:]
                    mask = "32"

                    obj = {"name": name, "ipv4": ipv4, "mask" : str(mask)}

                    appendIfAbsent(obj,objects)
                                        
                elif nextLine[:4] == ' nat':

                    name = line[15:].rstrip()

                    # Do not replace with appendIfAbsent method, appending only name and not the whole object
                    objExists = has_obj_nat.count(obj)
                    if objExists > 0:
                        pass
                    else:
                        has_obj_nat.append(name)
                
            elif not line:
                break

        #print(objects)
    return

def find_services():
    
    with open('../show_run.txt') as file:
        for line in file:

            if line[:14] == 'object service':
                nextLine = next(file, '').rstrip()

                if nextLine[13:24] == 'destination':
                    type = 'destination'
                    name = line[15:].strip()
                    protocol = nextLine[9:12]

                    if 'range' in nextLine:
                        port = nextLine[nextLine.find('range')+6:]
                    else:
                        port = nextLine[28:]
                    
                    obj = {"name": name, "protocol": protocol, "port" : port, 'type' : type}

                    appendIfAbsent(obj,services)

                elif nextLine[13:19] == 'source':
                    type = 'source'
                    name = line[15:].strip()
                    protocol = nextLine[9:12]
                    
                    if 'range' in nextLine:
                        port = nextLine[nextLine.find('range')+6:]
                    else:
                        port = nextLine[23:]

                    obj = {"name": name, "protocol": protocol, "port" : port, 'type' : type}
                    
                    appendIfAbsent(obj,services)
                
            elif not line:
                
                break
        #print(services)
    return

def find_object_groups():
    parse = CiscoConfParse("../show_run.txt")

    all_obj_grps = parse.find_objects(r"^object-group network")

    for obj in all_obj_grps:
        search = (str(obj)[19:-2])
        #print(parse.find_children(search))
        result = parse.find_children(search)

        groupName = result[0][21:]
        new_children = []

        for i in range(len(result)):
            if "network-object object" in result[i]:
                child = result[i][23:]
                #print(child)
                new_children.append(child)
            elif "network-object host" in result[i]:
                child = result[i][21:]
                #print(child)
                new_children.append(child)
            elif "network-object " in result[i]:
                child = result[i][16:]
                #print(child)
                mask_start = child.find(' ')

                ipv4 = child[:mask_start]
                mask = to_cidr(child[mask_start:])
                name = "INLINE_"+ child[:mask_start]+"_"+str(mask)

                obj = {"name": name, "ipv4": ipv4, "mask" : str(mask)}

                appendIfAbsent(obj,objects)
                
                new_children.append(name)
            else:
                pass

        children=new_children
        #print(groupName,children)
        
        group = {
            'name' : groupName,
            'children' : children
        }

        appendIfAbsent(group,net_groups)
    #print(net_groups)
    return
    
def find_service_groups():
    parse = CiscoConfParse("../show_run.txt")

    all_svc_grps = parse.find_objects(r"^object-group service")

    for svc in all_svc_grps:
        search = (str(svc)[19:-2])
        #print(parse.find_children(search))
        result = parse.find_children(search)

        groupName = result[0][21:]
        new_children = []

        for i in range(len(result)):
            if "destination" in result[i]:
                decalage = 11
                type = "destination"
            elif "source" in result[i]:
                decalage = 6
                type = 'source'

            if "service-object object" in result[i]:
                child = result[i][23:]
                new_children.append(child.rstrip())

            elif "service-object tcp-udp" in result[i]:
                port = find_port(result[i])
                
                protocol = "TCP-UDP"
                name = "INLINE_"+ protocol + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : protocol,
                    'port' : port,
                    'type' : type
                }

                appendIfAbsent(child,services)

                new_children.append(name)

            elif "service-object tcp" in result[i]:
                
                port = find_port(result[i])

                protocol = "TCP"
                name = "INLINE_"+ protocol + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : protocol,
                    'port' : port,
                    'type' : type
                }

                appendIfAbsent(child,services)

                new_children.append(name)

            elif "service-object udp" in result[i]:
                
                port = find_port(result[i])

                protocol = "UDP"
                name = "INLINE_"+ protocol + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : protocol,
                    'port' : port,
                    'type' : type
                }

                appendIfAbsent(child,services)

                new_children.append(name)

            else:
                pass

        children=new_children
        
        group = {
            'name' : groupName,
            'children' : children
        }

        appendIfAbsent(group,svc_groups)
    return

def is_grp_used():
    for group in net_groups:
        parse = CiscoConfParse("../show_run.txt")
        hits = parse.find_objects(group['name'])     
        
        false_hits = str(hits).split(" ").count("'object") + str(hits).split(" ").count("'object-group") + str(hits).split(" ").count("' network-object")
        
        objExists = len(hits) - false_hits

        if objExists > 0:
            appendIfAbsent(group,used_obj_groups)
        else:
            appendIfAbsent(group,unused_obj_groups)

    for group in svc_groups:
        parse = CiscoConfParse("../show_run.txt")
        hits = parse.find_objects(group['name'])        
        
        false_hits = str(hits).split(" ").count("'object") + str(hits).split(" ").count("'object-group") + str(hits).split(" ").count("' service-object")
        
        objExists = len(hits) - false_hits

        if objExists > 0:
            appendIfAbsent(group,used_svc_groups)
        else:
            appendIfAbsent(group,unused_svc_groups)

    return

def is_obj_used():
    #Check if object is in used group
    for obj in objects:
        for group in used_obj_groups:
            count = group['children'].count(obj['name'])

            if count > 0:
                appendIfAbsent(obj,used_objects)
                #Otherwise, check if object is in unused groups
            else:
                #print(obj)
                #print(unused_obj_groups)

                parse = CiscoConfParse("../show_run.txt")
                hits = parse.find_objects(obj['name'])
                
                false_hits = str(hits).split(" ").count("'object") + str(hits).split(" ").count("'object-group") + str(hits).split(" ").count("'network-object")

                #print(obj, len(hits), false_hits, known_appearances)

                if len(hits)-false_hits > 0:
                    appendIfAbsent(obj,used_objects)

                elif "INLINE_" in obj['name']:
                    ipv4 = obj['ipv4']
                    mask = to_netmask(obj['mask'])
                    to_search = ipv4 + " " + mask

                    hits_inline = parse.find_objects(to_search)
                    
                    if len(hits_inline) > 0:
                        appendIfAbsent(obj,used_objects)

                elif has_obj_nat.count(obj['name']) > 0:
                    appendIfAbsent(obj,used_objects)
                    appendIfAbsent(obj,objects)
                else:
                    appendIfAbsent(obj,unused_objects)

                #print(hits, obj)

    return

def is_svc_used():
        #Check if object is in used group
    for svc in services:
        for group in used_svc_groups:

            parse = CiscoConfParse("../show_run.txt")
            hits = parse.find_objects(svc['name'])

            count = group['children'].count(svc['name'])

            if count > 0:
                #print(svc, used_svc_groups)
                appendIfAbsent(svc,used_services)
                #print(svc, "REASON : IN USED GROUP", hits)
            else:
                name = svc['name']
                p_type = svc['type']
                protocol = svc['protocol']
                port = svc['port']

                srv_prot_type_port = "service "+ protocol + " " + p_type + " eq " + port
                grp_prot_type_port = "service-object " + protocol + " " + p_type + " eq " + port
                grp_srv_name = "object-group service " + name
                obj_srv_name = "object service " + name
                srv_obj_name = "service-object " + name

                false_hits_1 = re.findall(srv_prot_type_port, str(hits))
                false_hits_2 = re.findall(grp_prot_type_port, str(hits))
                false_hits_3 = re.findall(grp_srv_name, str(hits))
                false_hits_4 = re.findall(obj_srv_name, str(hits))
                false_hits_5 = re.findall(srv_obj_name, str(hits))

                total_false_hits = len(false_hits_1) + len(false_hits_2) + len(false_hits_3) + len(false_hits_4) + len(false_hits_5)

                if len(hits) > total_false_hits:
                    appendIfAbsent(svc,used_services)
                    #print(svc, "REASON : IN CONFIG", hits, len(hits), total_false_hits)
                elif "INLINE_" in svc['name']:
                    to_search = protocol + " " + p_type + " eq " + port
                    to_search2 = "eq " + port

                    hits_inline = parse.find_objects(to_search)
                    hits_inline2 = parse.find_objects(to_search2)

                    if len(hits_inline)+len(hits_inline2) > 0:
                        appendIfAbsent(svc,used_services)
                        #print(svc, "REASON : INLINE USED")
                    else:
                        appendIfAbsent(svc,unused_services)
                        #print(svc, "REASON : NOT USED")
                else:
                    appendIfAbsent(svc,unused_services)
    return

def get_token():
    with open('../user.txt') as creds:
        
        line = creds.readline()
        
        user = line.split(',')[0]
        pw = line.split(',')[1]

        url = "https://x.x.x.x/api/fdm/v6/fdm/token"

        payload = json.dumps({
        "grant_type": "password",
        "username": user,
        "password": pw
        })

        headers = {
        'Content-Type': 'application/json'
        }
        
        request = requests.request("POST", url, headers=headers, data=payload, verify=False)
        token = json.loads(request.text)['access_token']

        return token

def create_object_api(obj):
    token = get_token()
    url = "https://x.x.x.x/api/fdm/v6/object/networks?expanded=true&limit=9000"

    if "INLINE_" in obj['name']:
        name = obj['name'][7:]
    else:
        name = obj['name']

    if str(obj['mask']) == "32":
        subtype = "HOST"
        value = obj['ipv4']
        name  = "HOST_"+name
    else:
        subtype = "NETWORK"
        value = obj['ipv4']+"/"+str(obj['mask']).strip()
        name  = "NET_"+name

    payload = json.dumps({
    "name": name,
    "subType": subtype,
    "value": value,
    "type": "networkobject"
    })

    #print(payload)
    headers = {
    'X-auth-access-token': token,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer '+ token
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    print(response.text)

    return

def create_object_group_api(grp):

    token = get_token()
    url = "https://x.x.x.x/api/fdm/v6/object/networkgroups?expanded=true&limit=9000"

    headers = {
    'X-auth-access-token': token,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer '+ token
    }        

    name = "GRP_"+grp['name']
    children = grp['children']

    grp_obj = []

    for child in children:
        if "INLINE_" in child:
            child_name = child[7:]
        else:
            child_name = child
       
        if len(re.findall(child, str(objects))) > 0:
            type = "networkobject"
        elif len(re.findall(child, str(net_groups))) > 0:
            type = "networkobjectgroup"

        url_objects = "https://x.x.x.x/api/fdm/v6/object/networks?expanded=true&limit=9000"

        request = requests.request("GET", url_objects, headers=headers, data={}, verify=False)
        items = json.loads(request.text)['items']
        for item in items:
            if "NET_"+child_name in item["name"]:
                id = item["id"]
            if "HOST_"+child_name in item["name"]:
                id = item["id"]

        dict = { "name" : child_name, "id" : id, "type" : type }

        grp_obj.append(dict)

    payload = json.dumps({
        "name": name,
        "objects": grp_obj,
        "type": "networkobjectgroup"
    })

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    print(response.text)

    return

find_objects()
find_services()
find_object_groups()
find_service_groups()

#is_grp_used()
#is_obj_used()
#is_svc_used()

# for object in objects:
#     create_object_api(object)
#     print(object)

# for group in net_groups:
#     create_object_group_api(group)
#     print(group)

# print("############## USED OBJECT GROUPS ##################")
# print(used_obj_groups)
# print(net_groups)
# print("#######################################################")
# print("Groupes d'objets utilisés :", len(used_obj_groups))
# print("############## UNUSED OBJECT GROUPS ##################")
# print(unused_obj_groups)
# print("#######################################################")
# print("Groupes d'objets inutilisés :", len(unused_obj_groups))
# print("Groupes d'objets totaux :", len(net_groups))

print("############### USED OBJECTS #################")
print(used_objects)
print("#######################################################")
print("Objets utilisés :", len(used_objects))
print("############### UNUSED OBJECTS #################")
print(unused_objects)
print("#######################################################")
print("Objets inutilisés :", len(unused_objects))
print("Objets totaux :", len(objects))
print(objects)

# print("############## USED SERVICES GROUPS ##################")
# print(used_svc_groups)
# print("#######################################################")
# print("Groupes de services utilisés :", len(used_svc_groups))
# print("############## UNUSED SERVICE GROUPS ##################")
# print(unused_svc_groups)
# print("#######################################################")
# print("Groupes de services inutilisés :", len(unused_svc_groups))
# print("Groupes de services totaux :", len(svc_groups))

# print("############### USED SERVICES #################")
# print(used_services)
# print("#######################################################")
# print("Services utilisés :", len(used_services))
# print("############### UNUSED SERVICES #################")
# print(unused_services)
# print("#######################################################")
# print("Services inutilisés :", len(unused_services))
# print("################ SERVICES ###################")
# print(services)
# print("Services totaux :", len(services))