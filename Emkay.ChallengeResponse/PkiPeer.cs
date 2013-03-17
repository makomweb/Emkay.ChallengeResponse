using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Emkay.Pki
{
    public class PkiPeer : IPeer, IDisposable
    {
        private AesCryptoServiceProvider _provider = new AesCryptoServiceProvider();
        private readonly CngKey _privateKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
        private ECDiffieHellmanCng _algorithm;
        private ICryptoTransform _encryptor;
        private ICryptoTransform _decryptor;

        private ECDiffieHellmanCng Algorithm
        {
            get { return _algorithm ?? (_algorithm = new ECDiffieHellmanCng(_privateKey)); }
        }

        private ICryptoTransform Encryptor
        {
            get { return _encryptor ?? (_encryptor = _provider.CreateEncryptor()); }
        }

        private ICryptoTransform Decryptor
        {
            get { return _decryptor ?? (_decryptor = _provider.CreateDecryptor()); }
        }

        public byte[] PublicKey
        {
            get { return _privateKey.Export(CngKeyBlobFormat.EccPublicBlob); }
        }

        public byte[] Encipher(string plain, byte[] publicKey)
        {
            var raw = Encoding.UTF8.GetBytes(plain);
            using (var pubKey = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                return Encipher(raw, pubKey);
            }
        }

        public string Decipher(byte[] ciphered, byte[] publicKey)
        {
            using (var pubKey = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                var plain = Decipher(ciphered, pubKey);
                return Encoding.UTF8.GetString(plain);
            }
        }

        private byte[] Encipher(byte[] plain, CngKey publicKey)
        {
            var key = Algorithm.DeriveKeyMaterial(publicKey);
            _provider.Key = key;
            _provider.GenerateIV();

            using (var ms = new MemoryStream())
            {
                var cs = new CryptoStream(ms, Encryptor, CryptoStreamMode.Write);

                ms.Write(_provider.IV, 0, _provider.IV.Length);
                cs.Write(plain, 0, plain.Length);
                cs.Close();
                _provider.Clear();
                return ms.ToArray();
            }
        }

        private byte[] Decipher(byte[] ciphered, CngKey publicKey)
        {
            var nBytes = _provider.BlockSize >> 3;
            var iv = new byte[nBytes];
            for (var i = 0; i < iv.Length; i++)
                iv[i] = ciphered[i];

            var key = Algorithm.DeriveKeyMaterial(publicKey);

            _provider.Key = key;
            _provider.IV = iv;

            using (var ms = new MemoryStream())
            {
                var cs = new CryptoStream(ms, Decryptor, CryptoStreamMode.Write);
                cs.Write(ciphered, nBytes, ciphered.Length - nBytes);
                cs.Close();
                    
                _provider.Clear();

                return ms.ToArray();
            }
        }

        public void Dispose()
        {
            if (_provider != null)
                _provider.Dispose();
            _provider = null;

            if (_algorithm != null)
                _algorithm.Dispose();
            _algorithm = null;

            if (_encryptor != null)
                _encryptor.Dispose();
            _encryptor = null;

            if (_decryptor != null)
                _decryptor.Dispose();
            _decryptor = null;
        }
    }
}