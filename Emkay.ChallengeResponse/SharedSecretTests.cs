using System.Text;
using NUnit.Framework;

namespace Emkay.SharedSecret
{
    [TestFixture]
    public class SharedSecretTests
    {
        private SharedSecretPeer _alice;
        private SharedSecretPeer _bob;
        private EvalDoer _evalDoer;
        private string _message;
        private byte[] _ciphered;

        [SetUp]
        public void SetUp()
        {
            var sharedSecret = Encoding.ASCII.GetBytes("12345678");
            _alice = new SharedSecretPeer(sharedSecret);
            _bob = new SharedSecretPeer(sharedSecret);
            _evalDoer = new EvalDoer(sharedSecret);
            _message = "My secret message";
            _ciphered = _bob.Encipher(_message);
        }

        [Test]
        public void Intercepted_message_should_not_be_readable()
        {
            var intercepted = _evalDoer.Decipher(_ciphered);
            Assert.IsFalse(string.IsNullOrEmpty(intercepted));
            Assert.IsFalse(intercepted.Equals(_message));
        }

        [Test]
        public void Decipher_should_reveal()
        {
            var plain = _alice.Decipher(_ciphered);
            Assert.IsFalse(string.IsNullOrEmpty(plain));
            Assert.IsTrue(plain.Equals(_message));
        }
    }
}