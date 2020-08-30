using System;
using System.Reflection;

namespace SharpFox.Models
{
    public class Login
    {
        public int id { get; set; }
        public string hostname { get; set; }
        public string httpRealm { get; set; }
        public string formSubmitURL { get; set; }
        public string usernameField { get; set; }
        public string passwordField { get; set; }
        public string encryptedUsername { get; set; }
        public string encryptedPassword { get; set; }
        public string guid { get; set; }
        public int encType { get; set; }
        public long timeCreated { get; set; }
        public long timeLastUsed { get; set; }
        public long timePasswordChanged { get; set; }
        public int timesUsed { get; set; }
    }

    public class HistoryItem
    {
        public string host { get; set; }
        public int frequency { get; set; }
        public string prefix { get; set; }
    }

    public class Cookie
    {
        public string domain { get; set; }
        public long expirationDate { get; set; }
        public bool hostOnly { get; set; }
        public bool httpOnly { get; set; }
        public string name { get; set; }
        public string path { get; set; }
        public string sameSite { get; set; }
        public bool secure { get; set; }
        public bool session { get; set; }
        public string storeId { get; set; }
        public string value { get; set; }
        public int id { get; set; }

        public string ToJSON()
        {
            Type type = this.GetType();
            PropertyInfo[] properties = type.GetProperties();
            string[] jsonItems = new string[properties.Length]; // Number of items in EditThisCookie
            for (int i = 0; i < properties.Length; i++)
            {
                PropertyInfo property = properties[i];
                object[] keyvalues = { property.Name, property.GetValue(this, null) };
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
}
