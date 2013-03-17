using System;
using System.IO;
using System.Security.Cryptography;

namespace Emkay.SharedSecret
{
    public class SharedSecretPeer : IDisposable
    {
        private DESCryptoServiceProvider _provider = new DESCryptoServiceProvider();
     
        private readonly byte[] _sharedSecret;

        public SharedSecretPeer(byte[] presharedSecret)
        {
            _sharedSecret = presharedSecret;
        }

        public byte[] Encipher(string plain)
        {
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, _provider.CreateEncryptor(_sharedSecret, _sharedSecret), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plain);
                sw.Flush();
                cs.FlushFinalBlock();
                sw.Flush();
                return ms.ToArray();
            }
        }

        public string Decipher(byte[] crypted)
        {
            using (var ms = new MemoryStream(crypted))
            using (var cs = new CryptoStream(ms, _provider.CreateDecryptor(_sharedSecret, _sharedSecret), CryptoStreamMode.Read))
            {
                var sr = new StreamReader(cs);
                return sr.ReadToEnd();
            }
        }

        public void Dispose()
        {
            if (_provider != null)
                _provider.Dispose();
            _provider = null;
        }
    }
}
