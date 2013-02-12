using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace Emkay.ChallengeResponse
{
    static class Shared
    {
        public static string Secret = Guid.NewGuid().ToString();
    }

    class Peer
    {
        public string Challenge = Guid.NewGuid().ToString();

        public bool Authenticated(string challenge, string response)
        {
            var r = CalculateResponse(challenge, Shared.Secret);
            return string.Equals(response, r);
        }

        public string CalculateResponse(string challenge)
        {
            return CalculateResponse(challenge, Shared.Secret);
        }

        private static string CalculateResponse(string challenge, string secret)
        {
            var payload = challenge + secret;

            using (var md5 = MD5.Create())
            {
                var hashed = md5.ComputeHash(Encoding.Default.GetBytes(payload));
                return Encoding.Default.GetString(hashed);
            }
        }
    }

    class Client : Peer {}

    class Server : Peer {}

    [TestFixture]
    public class ChallengeResponseTests
    {
        [Test]
        public void Client_authenticates_via_challenge_response()
        {
            var s = new Server();
            var c = new Client();

            var response = c.CalculateResponse(s.Challenge);
            var authenticated = s.Authenticated(s.Challenge, response);

            Assert.IsTrue(authenticated, "Not authenticated!");
        }
    }
}
