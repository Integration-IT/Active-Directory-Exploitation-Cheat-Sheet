/*
 * Created by SharpDevelop.
 * User: Giuliano Cioffi <giuliano@108.bz>
 * Date: 28/07/2013
 * Time: 19:01
 * 
 */
using System;

namespace bz.OneOEight.SeBackupPrivilege
{
	class Program
	{
		public static void Main(string[] args) {
			bool retVal;
			
			
			retVal = SeBackupPrivilegeUtils.isSeBackupPrivilegeEnabled();
			Console.WriteLine(retVal ? "Yes!" : "no");
			SeBackupPrivilegeUtils.setSeBackupPrivilege(true);
			retVal = SeBackupPrivilegeUtils.isSeBackupPrivilegeEnabled();
			Console.WriteLine(retVal ? "Yes!" : "no");
			if(!retVal) {
				Console.WriteLine("SeBackupPrivilege is not enabled, giving up");
				return;
			}
			uint bytesCopied = 0;
			retVal = SeBackupPrivilegeUtils.CopyFile("c:/temp/x.txt", "c:/temp/y.txt", ref bytesCopied, true);
			if(retVal) {
				Console.WriteLine("Copied " + bytesCopied.ToString() + " bytes");
			}
		}
	}
}