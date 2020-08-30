using System;
using System.Data;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Security.Principal;
using System.IO;
using System.Reflection;
using CS_SQLite3;
using SharpChrome;
using SharpFox;
using SharpEdge;

namespace SharpWeb
{
    class Program
    {
        static void Usage()
        {
            string banner = @"
Usage:
    .\SharpWeb.exe arg0 [arg1 arg2 ...]

Arguments:
    all       - Retrieve all Chrome, FireFox and IE/Edge credentials.
    full      - The same as 'all'
    chrome    - Fetch saved Chrome logins.
    firefox   - Fetch saved FireFox logins.
    edge      - Fetch saved Internet Explorer/Microsoft Edge logins.
";
            Console.WriteLine(banner);
        }

        static void Main(string[] args)
        {

            string[] validArgs = { "all", "full", "chrome", "firefox", "-p", "edge" };

            bool getChrome = false;
            bool getFireFox = false;
            bool getEdge = false;
            string masterPassword = "";
            if (args.Length == 0)
            {
                Usage();
                return;
            }

            // Parse the arguments.
            for (int i = 0; i < args.Length; i++)
            {
                // Valid arg!
                string arg = args[i].ToLower();
                if (Array.IndexOf(validArgs, arg) != -1)
                {
                    if (arg == "all" || arg == "full")
                    {
                        getChrome = true;
                        getEdge = true;
                        getFireFox = true;
                    }
                    else if (arg == "chrome")
                    {
                        getChrome = true;
                    }
                    else if (arg == "firefox")
                    {
                        getFireFox = true;
                    }
                    else if (arg == "edge")
                    {
                        getEdge = true;
                    }
                    else if (arg == "-p")
                    {
                        masterPassword = args[i + 1]; 
                    }
                }
            }

            if (!getChrome && !getEdge && !getFireFox)
            {
                Usage();
                return;
            }

            if (getChrome)
            {
                Chrome.GetLogins();
            }

            if (getFireFox)
            {
                if (masterPassword != "")
                {
                    FireFox.GetLogins(masterPassword);
                }
                else
                {
                    FireFox.GetLogins();
                }
            }

            if (getEdge)
            {
                Edge.GetLogins();
            }
        }
    }
}
