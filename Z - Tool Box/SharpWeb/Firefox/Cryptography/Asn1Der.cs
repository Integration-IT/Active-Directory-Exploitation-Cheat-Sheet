namespace SharpFox.Cryptography
{
    using System.Collections.Generic;
    using System.Text;
    using System;
    using System.Globalization;

    public class Asn1Der
    {
        public enum Type
        {
            Sequence = 0x30,
            Integer = 0x02,
            BitString = 0x03, 
            OctetString = 0x04,
            Null = 0x05,
            ObjectIdentifier = 0x06
        }


        public Asn1DerObject Parse(byte[] dataToParse)
        {
            Asn1DerObject parsedData = new Asn1DerObject();

            for (int i = 0; i < dataToParse.Length; i++)
            {
                byte[] data;
                int len = 0;
                switch ((Asn1Der.Type)dataToParse[i])
                {
                    case Type.Sequence:
                        if (parsedData.Lenght == 0)
                        {
                            parsedData.Type = Type.Sequence;
                            parsedData.Lenght = dataToParse.Length - (i + 2);
                            data = new byte[parsedData.Lenght];
                        }
                        else
                        {
                            parsedData.objects.Add(new Asn1DerObject()
                            {
                                Type = Type.Sequence,
                                Lenght = dataToParse[i + 1]
                            });
                            data = new byte[dataToParse[i + 1]];
                        }
                        len = (data.Length > dataToParse.Length - (i + 2)) ? dataToParse.Length - (i + 2) : data.Length;
                        Array.Copy(dataToParse, i+2, data, 0, len);
                        parsedData.objects.Add(this.Parse(data));
                        i = i + 1 + dataToParse[i + 1];                        
                        break;
                    case Type.Integer:
                        parsedData.objects.Add(new Asn1DerObject()
                            {
                                Type = Type.Integer,
                                Lenght = dataToParse[i + 1]
                            });
                        data = new byte[dataToParse[i + 1]];
                        len = ((i + 2) + dataToParse[i + 1] > dataToParse.Length) ? dataToParse.Length - (i + 2) : dataToParse[i + 1];
                        Array.Copy(dataToParse, i + 2, data, 0, len);
                        var parsedDataArray = parsedData.objects.ToArray();
                        parsedData.objects[parsedDataArray.Length - 1].Data = data;
                        i = i + 1 + parsedData.objects[parsedDataArray.Length - 1].Lenght;
                        break;
                    case Type.OctetString:
                        parsedData.objects.Add(new Asn1DerObject()
                            {
                                Type = Type.OctetString,
                                Lenght = dataToParse[i + 1]
                            });
                        data = new byte[dataToParse[i + 1]];
                        len = ((i + 2) + dataToParse[i + 1] > dataToParse.Length) ? dataToParse.Length - (i + 2) : dataToParse[i + 1];
                        Array.Copy(dataToParse, i + 2, data, 0, len);
                        var parsedDataArrayTwo = parsedData.objects.ToArray();
                        parsedData.objects[parsedDataArrayTwo.Length - 1].Data = data;
                        i = i + 1 + parsedData.objects[parsedDataArrayTwo.Length - 1].Lenght;
                        break;
                    case Type.ObjectIdentifier:
                        parsedData.objects.Add(new Asn1DerObject()
                            {
                                Type = Type.ObjectIdentifier,
                                Lenght = dataToParse[i + 1]
                            });
                        data = new byte[dataToParse[i + 1]];
                        len = ((i+2) + dataToParse[i + 1] > dataToParse.Length) ? dataToParse.Length - (i + 2) : dataToParse[i + 1];
                        Array.Copy(dataToParse, i + 2, data, 0, len);
                        var parsedDataArrayThree = parsedData.objects.ToArray();
                        parsedData.objects[parsedDataArrayThree.Length - 1].Data = data;
                        i = i + 1 + parsedData.objects[parsedDataArrayThree.Length - 1].Lenght;
                        break;
                    default:
                        break;
                }
            }

            return parsedData;
        }
    }

    public class Asn1DerObject
    {
        public Asn1Der.Type Type { get; set; }
        public int Lenght { get; set; }
        public List<Asn1DerObject> objects { get; set; }
        public byte[] Data { get; set; }

        public Asn1DerObject()
        {
            this.objects = new List<Asn1DerObject>();
        }

        public override string ToString()
        {
            StringBuilder str = new StringBuilder();
            StringBuilder data = new StringBuilder();
            switch (this.Type)
            {
                case Asn1Der.Type.Sequence:
                    str.AppendLine("SEQUENCE {");
                    break;
                case Asn1Der.Type.Integer:
                    foreach (byte octet in this.Data)
                    {
                        //data.Append((int)octet);
                        data.AppendFormat("{0:X2}", octet);
                    }
                    str.AppendLine("\tINTEGER " + data);
                    data = new StringBuilder();
                    break;
                case Asn1Der.Type.OctetString:

                    foreach (byte octet in this.Data)
                    {
                        data.AppendFormat("{0:X2}", octet);
                    }
                    str.AppendLine("\tOCTETSTRING " + data.ToString());
                    data = new StringBuilder();
                    break;
                case Asn1Der.Type.ObjectIdentifier:
                    foreach (byte octet in this.Data)
                    {
                        data.AppendFormat("{0:X2}", octet);
                    }
                    str.AppendLine("\tOBJECTIDENTIFIER " + data.ToString());
                    data = new StringBuilder();
                    break;
                default:
                    break;
            }
            foreach (Asn1DerObject obj in this.objects)
            {
                str.Append(obj.ToString());
            }

            if (this.Type.Equals(Asn1Der.Type.Sequence))
            {
                str.AppendLine("}");
            }
            return str.ToString();
        }
    }
}
