/*
 * Created by SharpDevelop.
 * User: Giuliano Cioffi <giuliano@108.bz>
 * Date: 26/07/2013
 * Time: 10:50
 * 
 */
using System;
using System.Runtime.InteropServices;

namespace bz.OneOEight.SeBackupPrivilege
{
	public class SeBackupPrivilegeUtils
	{
		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern bool CloseHandle(IntPtr h);
		
		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
		                                                  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
		[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
		internal static extern IntPtr GetCurrentProcess();
		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		protected static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid,System.Text.StringBuilder lpName, ref int cchName);
		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			TOKEN_INFORMATION_CLASS TokenInformationClass,
			IntPtr TokenInformation,
			int TokenInformationLength,
			ref int ReturnLength);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
		                            uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool WriteFile(IntPtr hFile, byte [] lpBuffer,
		                             uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
		                             IntPtr lpOverlapped);
		
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
		private static extern IntPtr CreateFile(
			string lpFileName,
			EFileAccess dwDesiredAccess,
			EFileShare dwShareMode,
			IntPtr lpSecurityAttributes,
			ECreationDisposition dwCreationDisposition,
			EFileAttributes dwFlagsAndAttributes,
			IntPtr hTemplateFile);
		
		private enum EFileAccess : uint	{
			GenericRead = 0x80000000,
			GenericWrite = 0x40000000,
			GenericExecute = 0x20000000,
			GenericAll = 0x10000000,
		}
		
		private enum EFileShare : uint {
			None = 0x00000000,
			Read = 0x00000001,
			Write = 0x00000002,
			Delete = 0x00000004,
		}
		private enum ECreationDisposition : uint {
			New = 1,
			CreateAlways = 2,
			OpenExisting = 3,
			OpenAlways = 4,
			TruncateExisting = 5,
		}

		private enum EFileAttributes : uint	{
			Readonly = 0x00000001,
			Hidden = 0x00000002,
			System = 0x00000004,
			Directory = 0x00000010,
			Archive = 0x00000020,
			Device = 0x00000040,
			Normal = 0x00000080,
			Temporary = 0x00000100,
			SparseFile = 0x00000200,
			ReparsePoint = 0x00000400,
			Compressed = 0x00000800,
			Offline = 0x00001000,
			NotContentIndexed = 0x00002000,
			Encrypted = 0x00004000,
			Write_Through = 0x80000000,
			Overlapped = 0x40000000,
			NoBuffering = 0x20000000,
			RandomAccess = 0x10000000,
			SequentialScan = 0x08000000,
			DeleteOnClose = 0x04000000,
			BackupSemantics = 0x02000000,
			PosixSemantics = 0x01000000,
			OpenReparsePoint = 0x00200000,
			OpenNoRecall = 0x00100000,
			FirstPipeInstance = 0x00080000
		}

		protected enum TOKEN_INFORMATION_CLASS {
			TokenPrivileges = 3
		}
		
		protected struct TOKEN_PRIVILEGES {
			public UInt32 PrivilegeCount;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
			public LUID_AND_ATTRIBUTES[] Privileges;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		protected struct LUID_AND_ATTRIBUTES {
			public LUID Luid;
			public UInt32 Attributes;
		}

		[StructLayout(LayoutKind.Sequential)]
		protected struct LUID {
			public uint LowPart;
			public int HighPart;
		}
		
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		internal struct TokPriv1Luid {
			public int Count;
			public long Luid;
			public int Attr;
		}
		
		internal const int INVALID_HANDLE_VALUE = -1;

		internal const int ERROR_INSUFFICIENT_BUFFER = 122;
		
		internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
		internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
		internal const int TOKEN_QUERY = 0x00000008;
		internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
		
		private static void croak(string message) {
			throw new Exception(message + " - " + Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()).Message);
		}
		
		public static bool setSeBackupPrivilege(bool enable) {
			bool retVal;
			TokPriv1Luid tp;
			IntPtr htok = IntPtr.Zero;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok)) {
				throw new Exception("OpenProcessToken");
			}
			tp.Count = 1;
			tp.Luid = 0;

			if(!enable) {
				tp.Attr = SE_PRIVILEGE_DISABLED;
			} else {
				tp.Attr = SE_PRIVILEGE_ENABLED;
			}
			
			if(!LookupPrivilegeValue(null, "SeBackupPrivilege", ref tp.Luid)) {
				croak("LookupPrivilegeValue");
			}
			retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
			if(!retVal) {
				croak("AdjustTokenPrivileges");
			}
			return retVal;
		}

		
		public static bool isSeBackupPrivilegeEnabled() {
			bool retVal;
			IntPtr htok = IntPtr.Zero;
			TokPriv1Luid tp;
			tp.Count = 1;
			tp.Luid = 0;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ref htok)) {
				throw new Exception("OpenProcessToken");
			}
			if(!LookupPrivilegeValue(null, "SeBackupPrivilege", ref tp.Luid)) {
				croak("LookupPrivilegeValue");
			}
			
			int dwReturnLength = 0;
			if(!GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, ref dwReturnLength)) {
				if(Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER) {
					croak("GetTokenInformation");
				}
			}
			IntPtr TokenInformation = Marshal.AllocHGlobal(dwReturnLength);
			if(!GetTokenInformation(htok, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, dwReturnLength, ref dwReturnLength)) {
				croak("GetTokenInformation");
			}
			TOKEN_PRIVILEGES ThisPrivilegeSet = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));
			retVal = false;
			for (int index = 0; index < ThisPrivilegeSet.PrivilegeCount; index++ ) {
				LUID_AND_ATTRIBUTES laa = ThisPrivilegeSet.Privileges[index];
				if((laa.Luid.LowPart == tp.Luid) && (laa.Attributes & SE_PRIVILEGE_ENABLED) != 0) {
					retVal = true;
					break;
				}
			}
			Marshal.FreeHGlobal(TokenInformation);
			return retVal;
		}
		
		internal const int COPY_FILE_BUFSIZE = 4096;
		public static bool CopyFile(string inFileName, string outFileName, ref uint bytesCopied, bool overwrite) {
			IntPtr inFile;
			IntPtr outFile;
			inFile = CreateFile(
				inFileName,
				EFileAccess.GenericRead,
				0,
				IntPtr.Zero,
				ECreationDisposition.OpenExisting,
				EFileAttributes.Normal | EFileAttributes.BackupSemantics,
				IntPtr.Zero);
			if(inFile.ToInt32() == -1) {
				croak("Opening input file.");
			}
			
			outFile = CreateFile(
				outFileName,
				EFileAccess.GenericWrite,
				0,
				IntPtr.Zero,
				overwrite ? ECreationDisposition.CreateAlways : ECreationDisposition.New,
				EFileAttributes.Normal,
				IntPtr.Zero);
			if(outFile.ToInt32() == -1) {
				CloseHandle(inFile);
				croak("Error creating output file.");
			}
			
			byte[] buf = new byte[COPY_FILE_BUFSIZE];
			uint bytesRead;
			uint bytesWritten;
			bool readOk;
			bool writeOk;
			uint totalBytesWritten = 0;
			do {
				readOk = ReadFile(inFile, buf, COPY_FILE_BUFSIZE, out bytesRead, IntPtr.Zero);
				if(!readOk) {
					CloseHandle(inFile);
					CloseHandle(outFile);
					croak("ReadFile");
				}
				writeOk = WriteFile(outFile, buf, bytesRead, out bytesWritten, IntPtr.Zero);
				if(!writeOk) {
					CloseHandle(inFile);
					CloseHandle(outFile);
					croak("WriteFile");
				}
				totalBytesWritten += bytesWritten;
			} while (readOk && bytesRead != 0);
			
			if(!CloseHandle(inFile)) croak("Closing input file.");
			if(!CloseHandle(outFile)) croak("Closing output file.");
			
			bytesCopied = totalBytesWritten;
			return true;
		}
	}
}