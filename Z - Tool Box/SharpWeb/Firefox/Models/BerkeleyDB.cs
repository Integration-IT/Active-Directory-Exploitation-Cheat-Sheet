namespace SharpFox
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;

    public class BerkeleyDB
    {
        public string Version { get; set; }
        public List<KeyValuePair<string, string>> Keys { get; private set; }


        public BerkeleyDB(string FileName)
        {
            List<byte> entire = new List<byte>();
            Keys = new List<KeyValuePair<string, string>>();

            using (BinaryReader dbReader = new BinaryReader(File.OpenRead(FileName)))
            {

                int pos = 0;
                int length = (int)dbReader.BaseStream.Length;

                while (pos < length)
                {
                    entire.Add(dbReader.ReadByte());
                    pos += sizeof(byte);
                }
            }
            string magic = BitConverter.ToString(this.Extract(entire.ToArray(), 0, 4, false)).Replace("-", "");
            string version = BitConverter.ToString(this.Extract(entire.ToArray(), 4, 4, false)).Replace("-", "");
            int pageSize = BitConverter.ToInt32(this.Extract(entire.ToArray(), 12, 4, true),0);

            if (magic.Equals("00061561"))
            {
                Version = "Berkelet DB";

                if (version.Equals("00000002"))
                {
                    Version += " 1.85 (Hash, version 2, native byte-order)";
                }

                int nbKey = Int32.Parse(BitConverter.ToString(this.Extract(entire.ToArray(), 0x38, 4, false)).Replace("-", ""));
                int page = 1;

                while (Keys.Count < nbKey)
                {
                    string[] address = new string[(nbKey - Keys.Count) * 2];

                    for (int i = 0; i < (nbKey - Keys.Count) * 2; i++)
                    {
                        address[i] = BitConverter.ToString(this.Extract(entire.ToArray(), (pageSize * page) + 2 + (i * 2), 2, true)).Replace("-", "");
                    }

                    Array.Sort(address);

                    for (int i = 0; i < address.Length; i = i + 2)
                    {
                        int startValue = Convert.ToInt32(address[i], 16) + (pageSize * page);
                        int startKey = Convert.ToInt32(address[i + 1], 16) + (pageSize * page);
                        int end = ((i + 2) >= address.Length) ? pageSize + (pageSize * page) : Convert.ToInt32(address[i + 2], 16) + (pageSize * page);

                        string key = Encoding.ASCII.GetString(Extract(entire.ToArray(), startKey, end - startKey, false));
                        string value = BitConverter.ToString(Extract(entire.ToArray(), startValue, startKey - startValue, false));

                        if (key != null && key.Replace(" ", "") != String.Empty)
                        {
                            Keys.Add(new KeyValuePair<string, string>(key, value));
                        }

                    }
                    page++;
                }

            }
            else
            {
                Version = "Unknow database format";
            }

        }

        public string GetValueOfKey(string key)
        {
            foreach(var k in this.Keys)
            {
                if (k.Key == key)
                {
                    return k.Value;
                }
            }
            return String.Empty;
        }

        private byte[] Extract(Byte[] source, int start, int length, bool littleEndian)
        {
            byte[] dest = new byte[length];
            int j = 0;

            for (int i = start; i < start + length; i++)
            {
                dest[j] = source[i];
                j++;
            }

            if (littleEndian)
            {
                Array.Reverse(dest);
            }
            return dest;
        }

        private byte[] ConvertToLittleEndian(byte[] source)
        {
            Array.Reverse(source);
            return source;
        }
    }
}
