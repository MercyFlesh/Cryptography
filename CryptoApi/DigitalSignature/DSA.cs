using Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignature
{
    public class DSA
    {
        private readonly ICryptor _cryptor;
        private readonly IHash _hash;

        public DSA(ICryptor cryptor, IHash hash)
        {
            _cryptor = cryptor;
            _hash = hash;
        }

        public List<BigInteger> GetSignature(string text)
        {
            var hashCode = _hash.GetHash(text);
            return _cryptor.Encrypt(hashCode);
        }

        public bool VerifySignature(string text, List<BigInteger> encryptedHash)
        {
            var checkHashCode = _hash.GetHash(text);
            var realHashCode = _cryptor.Decrypt(encryptedHash);
            return checkHashCode == realHashCode;
        }
    }
}
