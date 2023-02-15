from ciscoconfparse import CiscoConfParse
import re
import socket
import struct

objects = []
net_groups = []
services = []
svc_groups = []

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
    return netmask


def find_objects():

    with open('../show_run.txt') as file:
        for line in file:

            if line[:14] == 'object network':
                nextLine = next(file, '').rstrip()

                if nextLine[:8] == ' subnet ':

                    mask_start = nextLine.find('255')

                    name = line[14:].strip()
                    ipv4 = nextLine[8:mask_start-1]
                    mask = to_cidr(nextLine[mask_start:])

                    obj = {"name": name, "ipv4": ipv4, "mask" : mask}

                    objExists = objects.count(obj)
                    if objExists > 0:
                        pass
                    else:
                        objects.append(obj)

                elif nextLine[:6] == ' host ':

                    name = line[14:].strip()
                    ipv4 = nextLine[6:]
                    mask = "32"

                    obj = {"name": name, "ipv4": ipv4, "mask" : mask}

                    objExists = objects.count(obj)
                    if objExists > 0:
                        pass
                    else:
                        objects.append(obj)
                    
                elif nextLine[:4] == ' nat':
                    pass
                
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

                    name = line[15:].strip()
                    proto = nextLine[9:12]

                    if 'range' in nextLine:
                        port = nextLine[nextLine.find('range')+6:]
                    else:
                        port = nextLine[28:]
                    
                    obj = {"name": name, "proto": proto, "port" : port}

                    services.append(obj)

                elif nextLine[13:19] == 'source':
                    name = line[15:].strip()
                    proto = nextLine[9:12]
                    
                    if 'range' in nextLine:
                        port = nextLine[nextLine.find('range')+6:]
                    else:
                        port = nextLine[23:]

                    obj = {"name": name, "protocol": proto, "port" : port}
                    
                    objExists = services.count(obj)
                    if objExists > 0:
                        pass
                    else:
                        services.append(obj)
                
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

                obj = {"name": name, "ipv4": ipv4, "mask" : mask}

                objExists = objects.count(obj)
                if objExists > 0:
                    pass
                else:
                    objects.append(obj)
                
                new_children.append(name)
            else:
                pass

        children=new_children
        #print(groupName,children)
        
        group = {
            'name' : groupName,
            'children' : children
        }

        net_groups.append(group)
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
            elif "source" in result[i]:
                decalage = 6

            if "service-object object" in result[i]:
                child = result[i][23:]
                new_children.append(child)

            elif "service-object tcp-udp" in result[i]:
                
                if "eq" in result[i]:
                    port = result[i][result[i].find('eq')+3:].rstrip()
                else:
                    print("PORT NOT EQUAL", result[i])
                    break

                proto = "TCP-UDP"
                name = "SVC_"+ proto + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : proto,
                    'port' : port
                }

                objExists = services.count(child)
                if objExists > 0:
                    pass
                else:
                    services.append(child)

                new_children.append(name)

            elif "service-object tcp" in result[i]:
                
                if "eq" in result[i]:
                    port = result[i][result[i].find('eq')+3:].rstrip()
                else:
                    print("PORT NOT EQUAL", result[i])
                    break

                proto = "TCP"
                name = "SVC_"+ proto + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : proto,
                    'port' : port
                }

                objExists = services.count(child)
                if objExists > 0:
                    pass
                else:
                    services.append(child)

                new_children.append(name)

            elif "service-object udp" in result[i]:
                
                if "eq" in result[i]:
                    port = result[i][result[i].find('eq')+3:].rstrip()
                else:
                    print("PORT NOT EQUAL", result[i])
                    break

                proto = "UDP"
                name = "SVC_"+ proto + "_"+ port
                child = {
                    'name' : name,
                    'protocol' : proto,
                    'port' : port
                }

                objExists = services.count(child)
                if objExists > 0:
                    pass
                else:
                    services.append(child)

                new_children.append(name)

            else:
                pass

        children=new_children
        #print(groupName,children)
        
        group = {
            'name' : groupName,
            'children' : children
        }

        svc_groups.append(group)
    #print(net_groups)
    return

def is_grp_used():
    for group in net_groups:
        parse = CiscoConfParse("../show_run.txt")
        hits = parse.find_objects(group['name'])     
        
        false_hits = str(hits).split(" ").count("'object") + str(hits).split(" ").count("'object-group") + str(hits).split(" ").count("' network-object")
        
        objExists = len(hits) - false_hits

        if objExists > 0:
            used_obj_groups.append(group)

        else:
            unused_obj_groups.append(group)

    for group in svc_groups:
        parse = CiscoConfParse("../show_run.txt")
        hits = parse.find_objects(group['name'])        
        
        false_hits = str(hits).split(" ").count("'object") + str(hits).split(" ").count("'object-group") + str(hits).split(" ").count("' service-object")
        
        objExists = len(hits) - false_hits


        if objExists > 0:
            used_svc_groups.append(group)
        else:
            unused_svc_groups.append(group)

    return

def is_obj_used():
    #Check if object is in used group
    for obj in objects:
        for group in used_obj_groups:
            count = group['children'].count(obj['name'])

            if count > 0:

                objInList = used_objects.count(obj)
                if objInList > 0:
                    pass
                else:
                    used_objects.append(obj)
                #Otherwise, check if object is in unused groups
            else:
                #print(obj)
                #print(unused_obj_groups)
                for ugroup in unused_obj_groups:
                    known_appearances = ugroup['children'].count(obj['name']) + 1 + count
                    #print(known_appearances, obj)

                    parse = CiscoConfParse("../show_run.txt")
                    hits = parse.find_objects(obj['name'])
                    
                    if len(hits) > known_appearances:
                        objInList = used_objects.count(obj)
                        if objInList > 0:
                            pass
                        else:
                            used_objects.append(obj)
                    else:
                        objInList = unused_objects.count(obj)
                        if objInList > 0:
                            pass
                        else:
                            unused_objects.append(obj)

                    #print(hits, obj)

    return

find_objects()
find_services()
find_object_groups()
find_service_groups()

is_grp_used()
is_obj_used()

#print(objects)
#print(net_groups)
#print(services)
#print(svc_groups)

print(used_obj_groups)
print("################################")
print(unused_obj_groups)

print(used_objects)
print("################################")
print(unused_objects)