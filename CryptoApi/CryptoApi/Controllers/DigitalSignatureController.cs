using DigitalSignature;
using Microsoft.AspNetCore.Mvc;
using System.Numerics;

namespace CryptoApi.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class DigitalSignatureController : ControllerBase
    {
        private readonly DSA _dsa;

        public DigitalSignatureController(DSA dsa)
        {
            _dsa = dsa;
        }

        [HttpPost]
        public IEnumerable<string> GetSignature(string text)
        {
            var result = _dsa.GetSignature(text);

            return result.Select(x => x.ToString()).ToList();
        }

        [HttpPost]
        public bool VerifySignature(string text, IEnumerable<string> signature)
        {
            var result = _dsa.VerifySignature(text, signature.Select(x => BigInteger.Parse(x)).ToList());

            return result;
        }
    }
}
