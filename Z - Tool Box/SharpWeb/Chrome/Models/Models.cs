using System;
using System.Reflection;

namespace SharpChrome.Models
{
    public class Cookie
    {
        private string _domain;
        private long _expirationDate;
        private bool _hostOnly;
        private bool _httpOnly;
        private string _name;
        private string _path;
        private string _sameSite;
        private bool _secure;
        private bool _session;
        private string _storeId;
        private string _value;
        private int _id;

        // Getters and setters
        public string Domain
        {
            get { return _domain; }
            set { _domain = value; }
        }
        public long ExpirationDate
        {
            get { return _expirationDate; }
            set { _expirationDate = value; }
        }
        public bool HostOnly
        {
            get { return _hostOnly; }
            set { _hostOnly = value; }
        }
        public bool HttpOnly
        {
            get { return _httpOnly; }
            set { _httpOnly = value; }
        }
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }
        public string Path
        {
            get { return _path; }
            set { _path = value; }
        }
        public string SameSite
        {
            get { return _sameSite; }
            set { _sameSite = value; }
        }
        public bool Secure
        {
            get { return _secure; }
            set { _secure = value; }
        }
        public bool Session
        {
            get { return _session; }
            set { _session = value; }
        }
        public string StoreId
        {
            get { return _storeId; }
            set { _storeId = value; }
        }
        public string Value
        {
            get { return _value; }
            set { _value = value; }
        }
        public int Id
        {
            get { return _id; }
            set { _id = value; }
        }

        public string ToJSON()
        {
            Type type = this.GetType();
            PropertyInfo[] properties = type.GetProperties();
            string[] jsonItems = new string[properties.Length]; // Number of items in EditThisCookie
            for (int i = 0; i < properties.Length; i++)
            {
                PropertyInfo property = properties[i];
                object[] keyvalues = { property.Name[0].ToString().ToLower() + property.Name.Substring(1, property.Name.Length - 1), property.GetValue(this, null) };
                string jsonString = "";
                if (keyvalues[1].GetType() == typeof(String))
                {
                    jsonString = String.Format("\"{0}\": \"{1}\"", keyvalues);
                }
                else if (keyvalues[1].GetType() == typeof(Boolean))
                {
                    keyvalues[1] = keyvalues[1].ToString().ToLower();
                    jsonString = String.Format("\"{0}\": {1}", keyvalues);
                }
                else
                {
                    jsonString = String.Format("\"{0}\": {1}", keyvalues);
                }
                jsonItems[i] = jsonString;
            }
            string results = "{" + String.Join(", ", jsonItems) + "}";
            return results;
        }
    }

    public class HostCookies
    {
        private Cookie[] _cookies;
        private string _hostName;

        public Cookie[] Cookies
        {
            get { return _cookies; }
            set { _cookies = value; }
        }

        public string HostName
        {
            get { return _hostName; }
            set { _hostName = value; }
        }

        public string ToJSON()
        {
            string[] jsonCookies = new string[this.Cookies.Length];
            for (int i = 0; i < this.Cookies.Length; i++)
            {
                this.Cookies[i].Id = i + 1;
                jsonCookies[i] = this.Cookies[i].ToJSON();
            }
            return "[" + String.Join(",", jsonCookies) + "]";
        }
    }
}