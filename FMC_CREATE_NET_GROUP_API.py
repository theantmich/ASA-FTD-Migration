import json
import requests

url = "URL_OF_FMC"

### Group file format must be NAME;DESC
group_file = open("groups_desc.csv", "r")

### Member file format must be PARENT_GROUP_NAME;NAME;ID;TYPE
# If a member is in two groups, create two entries
member_file = open("portgroups_to_import.txt", "r")

### Initialize arrays to stock group and members from files
group_list = []
member_list = []

for line in group_file:
    group_list.append(line.strip())
    
for line in member_file:
    member_list.append(line.strip()) 
    
#print(group_list)
    


    
for group in group_list:
    
    ### For each group to be created, add name, description for the group and prepare the array for the members
    
    json_members = {"name":group.split(";")[0], "description":group.split(";")[1]}
    json_members["objects"] = []

    for member in member_list:
        
        ### Verification to see if each member belongs in the group from the group list
        if group.split(";")[0] == member.split(";")[0]:
            
            # If member belongs in group, append type, name and object ID in the "objects" array. Repeat for every member
            type = member.split(";")[3].strip()
            name = member.split(";")[1].strip()
            id = member.split(";")[2].strip()
            
            json_members["objects"].append({
                "type": type,
                "name": name,
                "id": id
            })
     
    ### Printed output is a dictionary formated for JSON. Can be POSTed in bulk to the FMC
    ### The output contains, for each group, the complete list of members to be added in the following format :
    ### {'name': '', 'description': '', 'objects': [{'type': '', 'name': '', 'id': ''}, {'type': '', 'name': '', 'id': ''}]}
    print(json_members)
        
    
