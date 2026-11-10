using HPE.Extensions.Configuration.CredentialManager;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecretsManager
{
    static class SecretStore
    {
        // Entropy specifica dell'app: non è un segreto, ma evita che un
        // blob DPAPI generico di un'altra app venga accettato per sbaglio.
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes(AppConstants.AppSeed);

        public static byte[] Protect(Credential c, DataProtectionScope scope)
        {
            byte[] plain;
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms, Encoding.UTF8))
                {
                    bw.Write(c.Username);
                    bw.Write(c.Password);
                }
                plain = ms.ToArray();
            }
            try { return ProtectedData.Protect(plain, Entropy, scope); }
            finally { Array.Clear(plain, 0, plain.Length); }
        }

        public static Credential Unprotect(byte[] blob, DataProtectionScope scope)
        {
            var plain = ProtectedData.Unprotect(blob, Entropy, scope);
            try
            {
                using (var br = new BinaryReader(new MemoryStream(plain), Encoding.UTF8))
                {
                    var user = br.ReadString();
                    var secret = br.ReadString();

                    return new Credential(user)
                    {
                        Password = secret
                    };
                }
            }
            finally { Array.Clear(plain, 0, plain.Length); }
        }
    }
}
