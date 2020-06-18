/*
 * Created by SharpDevelop.
 * User: Giuliano Cioffi <giuliano@108.bz>
 * Date: 27/07/2013
 * Time: 19:04
 * 
 */
using System;
using System.Management;
using System.Management.Automation;

namespace bz.OneOEight.SeBackupPrivilege
{
	public class FileUtils
	{
		public static string expandPath(string cwd, string fileName) {
			bool absolute = false;
			if (fileName.IndexOf('/') == 0) absolute = true;
			if (fileName.IndexOf('\\') == 0) absolute = true;
			if (fileName.IndexOf(':') == 1) absolute = true;
			if(!absolute) {
				//Console.WriteLine("+++ " + cwd + "/" + fileName);
				return(cwd + "/" + fileName);
			} else {
				//Console.WriteLine("+++ " + fileName);
				return(fileName);
			}
		}
	}
	
	[Cmdlet(VerbsCommon.Get, "SeBackupPrivilege")]
	public class Get_SeBackupPrivilege : Cmdlet
	{
		protected override void EndProcessing() {
			bool retVal = SeBackupPrivilegeUtils.isSeBackupPrivilegeEnabled();
			Console.WriteLine("SeBackupPrivilege is " + (retVal ? "enabled" : "disabled" ));
		}
	}
	
	[Cmdlet(VerbsCommon.Set, "SeBackupPrivilege")]
	public class Set_SeBackupPrivige : Cmdlet
	{
		[Parameter(HelpMessage = "Disable SeBackupPrivilege instead of enabling it")]
		public SwitchParameter Disable;
		protected override void EndProcessing() {
			bool retVal = SeBackupPrivilegeUtils.setSeBackupPrivilege(!Disable.ToBool());
		}
	}
	
	[Cmdlet(VerbsCommon.Copy, "FileSeBackupPrivilege")]
	public class Copy_FileSeBackupPrivilege : PSCmdlet
	{
		[Parameter(HelpMessage = "Input file name", Position = 1)]
		public string InFile;
		[Parameter(HelpMessage = "Output file name", Position = 2)]
		public string OutFile;
		[Parameter(HelpMessage = "Overwrite output file if it exists")]
		public SwitchParameter Overwrite;
		protected override void EndProcessing() {
			uint bytesCopied = 0;
			bool retVal;
			string cwd = this.SessionState.Path.CurrentFileSystemLocation.Path;
			retVal = SeBackupPrivilegeUtils.CopyFile(FileUtils.expandPath(cwd,InFile), FileUtils.expandPath(cwd,OutFile), ref bytesCopied, Overwrite.ToBool());
			if(retVal) {
				Console.WriteLine("Copied " + bytesCopied.ToString() + " bytes");
			}
		}
	}
}