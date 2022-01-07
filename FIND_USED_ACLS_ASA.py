from ciscoconfparse import CiscoConfParse

parse = CiscoConfParse('asa1_acls.txt', syntax='asa')

ACL_UNUSED = 0
ACL_USED = 0 
ACL_PARTIAL_USED = 0


DICT_ACL_UNUSED = {
'ACE' : [],
'SUB' : []
}

DICT_ACL_USED = {
'ACE' : [],
'SUB' : []
}

DICT_ACL_PARTIAL_USED = {
'ACE' : [],
'SUB' : []
}


for lines in parse.find_objects(f'^access-list .*'):

    if ("remark" in lines.text) or ("elements" in lines.text):
        pass

    elif "hitcnt=0" in lines.text:
        DICT_ACL_UNUSED['ACE'].append(lines.text)
        ACL_UNUSED +=1

    else:
        DICT_NO_HIT = []
        DICT_HIT    = []

        for subacl in lines.children:
            if "hitcnt=0" in subacl.text:
                DICT_NO_HIT.append(subacl.text)
            else:
                DICT_HIT.append(subacl.text)

        if len(DICT_NO_HIT) == 0:
            DICT_ACL_USED['ACE'].append(lines.text)
            ACL_USED +=1

        else:
            DICT_ACL_PARTIAL_USED['ACE'].append(lines.text)
            for x in DICT_HIT:
                DICT_ACL_PARTIAL_USED['SUB'].append(x)
            for y in DICT_NO_HIT:
                DICT_ACL_PARTIAL_USED['SUB'].append(y)
            
            ACL_PARTIAL_USED +=1




print(ACL_UNUSED)
print(ACL_USED)
print(ACL_PARTIAL_USED)


for element in DICT_ACL_USED['ACE']:
    print(element)


for element in DICT_ACL_PARTIAL_USED['ACE']:
    print(element)



























"""# ECRITURE DES REGLES UNUSED #
if len(DICT_UNUSED_ACL['ACE']) == 1:
    FILE_UNUSED.write(str(DICT_UNUSED_ACL['ACE'][0]) + "\n")

# ECRITURE DES REGLES USED #
if len(DICT_USED_ACL['ACE']) == 1:
    FILE_USED.write(str(DICT_USED_ACL['ACE'][0]) + "\n")

# ECRITURE DES REGLES PARTIAL USED #
if len(DICT_PARTIAL_USED_ACL['ACE']) == 1:
    FILE_PARTIAL.write(DICT_PARTIAL_USED_ACL['ACE'][0] + "\n")
    for z in DICT_PARTIAL_USED_ACL['SUB']:
        FILE_PARTIAL.write(z + "\n")"""
