using Microsoft.AspNetCore.Mvc;
using System.Numerics;
using System.Text.Json;
using RSA;

namespace CryptoApi.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class RSAController : ControllerBase
    {
        private readonly RSACryptor _cryptor;

        public RSAController(RSACryptor cryptor)
        {
            _cryptor = cryptor;
        }

        [HttpPost]
        public IEnumerable<string> Encrypt(string message)
        {
            var result = _cryptor.Encrypt(message);

            return result.Select(x => x.ToString()).ToList();
        }

        [HttpPost]
        public string Decrypt(IEnumerable<string> encryptedMessage)
        {
            var result = _cryptor.Decrypt(encryptedMessage.Select(x => BigInteger.Parse(x)).ToList());

            return result;
        }
    }
}