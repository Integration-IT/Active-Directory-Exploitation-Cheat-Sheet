namespace SharpFox.Cryptography
{
    using System.IO;
    using System.Security.Cryptography;

    public class TripleDESHelper
    {
        public static string DESCBCDecryptor(byte[] key, byte[] iv, byte[] input)
        {
            string plaintext = null;

            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = key;
                tdsAlg.IV = iv;
                tdsAlg.Mode = CipherMode.CBC;
                tdsAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }

        public static byte[] DESCBCDecryptorByte(byte[] key, byte[] iv, byte[] input)
        {
            byte[] decrypted = new byte[512];

            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = key;
                tdsAlg.IV = iv;
                tdsAlg.Mode = CipherMode.CBC;
                tdsAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        csDecrypt.Read(decrypted, 0, decrypted.Length);                       
                    }
                }

            }

            return decrypted;
        }
    }
}
