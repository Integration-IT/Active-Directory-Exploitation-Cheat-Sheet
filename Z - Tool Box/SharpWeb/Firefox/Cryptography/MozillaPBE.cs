namespace SharpFox.Cryptography
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Security.Cryptography;

    public class MozillaPBE
    {
        private byte[] GlobalSalt { get; set; }
        private byte[] MasterPassword { get; set; }
        private byte[] EntrySalt { get; set; }
        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }

        public MozillaPBE(byte[] GlobalSalt, byte[] MasterPassword, byte[] EntrySalt)
        {
            this.GlobalSalt = GlobalSalt;
            this.MasterPassword = MasterPassword;
            this.EntrySalt = EntrySalt;
        }

        public void Compute()
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] GLMP; // GlobalSalt + MasterPassword
            byte[] HP; // SHA1(GLMP)
            byte[] HPES; // HP + EntrySalt
            byte[] CHP; // SHA1(HPES)
            byte[] PES; // EntrySalt completed to 20 bytes by zero
            byte[] PESES; // PES + EntrySalt
            byte[] k1;
            byte[] tk;
            byte[] k2;
            byte[] k; // final value conytaining key and iv

            //GLMP
            GLMP = new byte[this.GlobalSalt.Length + this.MasterPassword.Length];
            Array.Copy(this.GlobalSalt, 0, GLMP, 0, this.GlobalSalt.Length);
            Array.Copy(this.MasterPassword, 0, GLMP, this.GlobalSalt.Length, this.MasterPassword.Length);

            //HP
            HP = sha.ComputeHash(GLMP);
            //HPES
            HPES = new byte[HP.Length + this.EntrySalt.Length];
            Array.Copy(HP, 0, HPES, 0, HP.Length);
            Array.Copy(this.EntrySalt, 0, HPES, HP.Length, this.EntrySalt.Length);
            //CHP
            CHP = sha.ComputeHash(HPES);
            //PES
            PES = new byte[20];
            Array.Copy(this.EntrySalt, 0, PES, 0, this.EntrySalt.Length);
            for (int i = this.EntrySalt.Length; i < 20; i++)
            {
                PES[i] = 0;
            }
            //PESES
            PESES = new byte[PES.Length + this.EntrySalt.Length];
            Array.Copy(PES, 0, PESES, 0, PES.Length);
            Array.Copy(this.EntrySalt, 0, PESES, PES.Length, this.EntrySalt.Length);

            using (HMACSHA1 hmac = new HMACSHA1(CHP))
            {
                //k1
                k1 = hmac.ComputeHash(PESES);
                //tk
                tk = hmac.ComputeHash(PES);
                //tkES
                byte[] tkES = new byte[tk.Length + this.EntrySalt.Length];
                Array.Copy(tk, 0, tkES, 0, tk.Length);
                Array.Copy(this.EntrySalt, 0, tkES, tk.Length, this.EntrySalt.Length);
                //k2
                k2 = hmac.ComputeHash(tkES);
            }

            //k
            k = new byte[k1.Length + k2.Length];
            Array.Copy(k1, 0, k, 0, k1.Length);
            Array.Copy(k2, 0, k, k1.Length, k2.Length);

            this.Key = new byte[24];

            for (int i = 0; i < this.Key.Length; i++)
            {
                this.Key[i] = k[i];
            }

            this.IV = new byte[8];
            int j = this.IV.Length - 1;

            for (int i = k.Length - 1; i >= k.Length - this.IV.Length; i--)
            {
                this.IV[j] = k[i];
                j--;
            }
        }
    }
}
