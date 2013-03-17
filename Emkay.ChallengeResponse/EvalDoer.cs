using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Emkay.SharedSecret
{
    public class EvalDoer : IDisposable
    {
        private readonly byte[] _sharedSecret;

        private DESCryptoServiceProvider _provider = new DESCryptoServiceProvider();

        public EvalDoer(byte[] sharedSecret)
        {
            _sharedSecret = sharedSecret;
        }

        public string Decipher(byte[] crypted)
        {
            using (var ms = new MemoryStream(crypted))
            {
                using (var cs = new CryptoStream(ms, _provider.CreateDecryptor(_sharedSecret, _sharedSecret), CryptoStreamMode.Read))
                {
                    var sr = new StreamReader(cs);
                    return sr.ReadToEnd();
                }
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

namespace Emkay.Pki
{
    public class EvalDoer
    {
        public string Decipher(byte[] ciphered, byte[] publicKey)
        {
            return Encoding.UTF8.GetString(ciphered);
        }
    }
}