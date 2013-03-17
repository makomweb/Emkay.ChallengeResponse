namespace Emkay.Pki
{
    public interface IPeer
    {
        byte[] PublicKey { get; }

        byte[] Encipher(string plain, byte[] publicKey);

        string Decipher(byte[] ciphered, byte[] publicKey);
    }
}