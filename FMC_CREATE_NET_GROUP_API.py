import csv
import json

group_file = open("groups_desc.csv", "r")
member_file = open("portgroups_to_import.txt", "r")

match = 0
id_count = 0

data = {}

group_list = []
member_list = []

for line in group_file:
    group_list.append(line.strip())
    
for line in member_file:
    member_list.append(line.strip()) 
    
print(group_list)
    

    
for group in group_list:

    #print("NAME", group.split(";")[0])
    #print("DESC", group.split(";")[1])
    
    
    json_members = {"name":group.split(";")[0], "description":group.split(";")[1]}
    json_members["objects"] = []
    match = 0
    id_count = 0

    for member in member_list:
        
        if group.split(";")[0] == member.split(";")[0]:
            
            type = member.split(";")[3].strip()
            name = member.split(";")[1].strip()
            id = member.split(";")[2].strip()
            
            json_members["objects"].append({
                "type": type,
                "name": name,
                "id": id
            })
            
    if match == id_count:
        print(json_members)
        
