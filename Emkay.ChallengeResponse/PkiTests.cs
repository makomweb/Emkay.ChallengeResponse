using NUnit.Framework;

namespace Emkay.Pki
{
    [TestFixture]
    public class PkiTests
    {
        private IPeer _alice;
        private IPeer _bob;
        private IPeer _evalDoer;
        private byte[] _ciphered;
        private string _message;

        [SetUp]
        public void SetUp()
        {
            _alice = new PkiPeer();
            _bob = new PkiPeer();
            _evalDoer = new PkiPeer();
            _message = "My secret message";
            _ciphered = _bob.Encipher(_message, _alice.PublicKey);
        }

        [Test]
        public void Intercepted_message_should_not_be_readable()
        {
            var intercepted = _evalDoer.Decipher(_ciphered, _bob.PublicKey);
            Assert.IsFalse(string.IsNullOrEmpty(intercepted));
            Assert.IsFalse(intercepted.Equals(_message));
        }

        [Test]
        public void Decipher_should_reveal()
        {
            var plain = _alice.Decipher(_ciphered, _bob.PublicKey);
            Assert.IsFalse(string.IsNullOrEmpty(plain));
            Assert.IsTrue(plain.Equals(_message));
        }
    }
}
