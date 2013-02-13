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

        public bool Authenticate(string challenge, string response)
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

    class Bob : Peer {}

    class Alice : Peer {}

    [TestFixture]
    public class ChallengeResponseTests
    {
        [Test]
        public void Authenticate_via_challenge_response()
        {
            var alice = new Alice();
            var bob = new Bob();

            var response = bob.CalculateResponse(alice.Challenge);
            var authenticated = alice.Authenticate(alice.Challenge, response);

            Assert.IsTrue(authenticated, "Not authenticated!");
        }
    }

    class Server : Peer
    {
        public bool CanElevate(string id)
        {
            return string.Equals(id, "1");
        }

        public bool CanElevate(string challenge, string response, string id)
        {
            return Authenticate(challenge, response) && CanElevate(id);
        }
    }

    class Client : Peer
    {
        public string Id { get; private set; }

        public Client(string id = "1")
        {
            Id = id;
        }
    }

    class Proxy
    {
        public bool CanElevate(string id)
        {
            return true;
        }

        public string Challenge
        {
            get { return "foobar"; }
        }

        public bool CanElevate(string challenge, string response, string id)
        {
            return true;
        }

        public string CalculateResponse(string challenge)
        {
            return "Something";
        }
    }

    [TestFixture]
    public class ElevationTests
    {
        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = false)]
        public bool Ask_server_if_client_can_elevate(string clientId)
        {
            var server = new Server();
            var client = new Client(clientId);
            return server.CanElevate(client.Id);
        }

        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = true)]
        public bool Ask_proxy_if_client_can_elevate(string clientId)
        {
            var proxy = new Proxy();
            var client = new Client(clientId);
            return proxy.CanElevate(client.Id);
        }

        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = false)]
        public bool Ask_server_if_client_can_elevate_using_challenge_response(string clientId)
        {
            var server = new Server();
            var client = new Client(clientId);

            var response = client.CalculateResponse(server.Challenge);
            return server.CanElevate(server.Challenge, response, client.Id);
        }

        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = true)]
        public bool Ask_proxy_if_client_can_elevate_using_challenge_response(string clientId)
        {
            var proxy = new Proxy();
            var client = new Client(clientId);

            var response = client.CalculateResponse(proxy.Challenge);
            return proxy.CanElevate(proxy.Challenge, response, client.Id);
        }

        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = false)]
        public bool Ask_server_for_elevation_after_beeing_authenticated(string clientId)
        {
            var server = new Server();
            var client = new Client(clientId);

            var response = server.CalculateResponse(client.Challenge);            
            Assert.IsTrue(client.Authenticate(client.Challenge, response), "Server is not authenticated!");
            return server.CanElevate(client.Id);
        }

        [TestCase("1", ExpectedResult = true)]
        [TestCase("2", ExpectedResult = true)]
        [ExpectedException(typeof(InvalidOperationException))]
        public bool Ask_proxy_for_elevation_after_beeing_authenticated(string clientId)
        {
            var proxy = new Proxy();
            var client = new Client(clientId);

            var response = proxy.CalculateResponse(client.Challenge);
            
            if (!client.Authenticate(client.Challenge, response))
                throw new InvalidOperationException("Server is not authenticated!");

            return proxy.CanElevate(client.Id);
        }
    }
}
