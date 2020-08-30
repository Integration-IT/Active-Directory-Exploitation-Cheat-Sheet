namespace SharpFox
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Globalization;

    public class PasswordCheck
    {
        public string EntrySalt { get; private set; }
        public string OID { get; private set; }
        public string Passwordcheck { get; private set; }

        public PasswordCheck(string DataToParse)
        {
            int EntrySaltLength = Int32.Parse(DataToParse.Substring(2, 2), NumberStyles.HexNumber)*2;
            this.EntrySalt = DataToParse.Substring(6, EntrySaltLength);

            int OIDLength = DataToParse.Length - (6 + EntrySaltLength + 36);
            this.OID = DataToParse.Substring(6 + EntrySaltLength + 36, OIDLength);

            this.Passwordcheck = DataToParse.Substring(6 + EntrySaltLength + 4 + OIDLength);
        }
    }
}
