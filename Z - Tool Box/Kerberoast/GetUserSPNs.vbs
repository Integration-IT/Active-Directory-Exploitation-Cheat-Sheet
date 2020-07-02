' Edits by Tim Medin
' File:     GetUserSPNS.vbs
' Contents: Query the domain to find SPNs that use User accounts
' Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
'           The password hash used with Computer accounts are infeasible to 
'           crack; however, if the User account associated with an SPN may have
'           a crackable password. This tool will find those accounts. You do not
'           need any special local or domain permissions to run this script. 
'           This script on a script supplied by Microsoft (details below).
' History:    2014/11/12     Tim Medin    Created
'
' Original Script Details:
' Copyright (c) Microsoft Corporation 2004 -
' File:                querySpn.vbs
' Contents:     Query a given SPN in a given forest to find the owners
' History:         7/7/2004     Craig Wiand     Created        

Option Explicit         
Dim oConnection, oCmd, oRecordSet
Dim oGC, oNSP
Dim strGCPath, strClass, strADOQuery
Dim vObjClass, vSPNs, vName

ParseCommandLine()

'--- Set up the connection ---
Set oConnection = CreateObject("ADODB.Connection")
Set oCmd = CReateObject("ADODB.Command")
oConnection.Provider = "ADsDSOObject"
oConnection.Open "ADs Provider"
Set oCmd.ActiveConnection = oConnection
oCmd.Properties("Page Size") = 1000

'--- Build the query string ---
strADOQuery = "<" + strGCPath + ">;(&(!objectClass=computer)(servicePrincipalName=*));" & _
        "dnsHostName,distinguishedName,servicePrincipalName,objectClass," & _
                "samAccountName;subtree"
oCmd.CommandText = strADOQuery

'--- Execute the query for the object in the directory ---
Set oRecordSet = oCmd.Execute
If oRecordSet.EOF and oRecordSet.Bof Then
  Wscript.Echo "No SPNs found!"
  Wscript.Quit 0
End If

While Not oRecordset.Eof
  Wscript.Echo oRecordset.Fields("distinguishedName")
  'vObjClass = oRecordset.Fields("objectClass")
  'strClass = vObjClass( UBound(vObjClass) )
  'Wscript.Echo "Class: " & strClass
  If UCase(strClass) = "COMPUTER" Then
    Wscript.Echo "Computer DNS: " & oRecordset.Fields("dnsHostName")
  Else
    Wscript.Echo "User Logon: " & oRecordset.Fields("samAccountName")
  End If

  '--- Display the SPNs on the object --- 
  vSPNs = oRecordset.Fields("servicePrincipalName")
  For Each vName in vSPNs
    Wscript.Echo "-- " + vName
  Next
  Wscript.Echo
  oRecordset.MoveNext
Wend

oRecordset.Close
oConnection.Close

Sub ShowUsage()
     Wscript.Echo " USAGE:        " & WScript.ScriptName & " SpnToFind [GC Servername or Forestname]"
     Wscript.Echo
     Wscript.Echo "                     " & WScript.ScriptName
     Wscript.Echo "                     " & WScript.ScriptName & " Corp.com"
     Wscript.Quit 0
End Sub

Sub ParseCommandLine()
  If WScript.Arguments.Count = 1 Then
    If WScript.Arguments(0) = "-h" Or WScript.Arguments(0) = "--help" Or WScript.Arguments(0) = "-?" Or WScript.Arguments(0) = "/?" Then
        ShowUsage()
    Else
      strGCPath = "GC://" & WScript.Arguments(1)
    End If
  ElseIf WScript.Arguments.Count = 0 Then
    ' Set the GC
    Set oNSP = GetObject("GC:")
    For Each oGC in oNSP
        strGCPath = oGC.ADsPath
    Next
  Else
      ShowUsage()
  End If

End Sub