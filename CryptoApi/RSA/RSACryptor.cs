using Domain.Interfaces;
using System.Numerics;
using System.Text;

namespace RSA
{
    public class RSACryptor : ICryptor
    {
        private readonly BigInteger p;
        private readonly BigInteger q;
        private readonly BigInteger n;
        private readonly BigInteger phi;
        private readonly BigInteger e;
        private readonly BigInteger d;

        public RSACryptor()
        {
            p = 379752279407;
            q = 400946909513;
            n = p * q;
            phi = (p - 1) * (q - 1);
            
            

            e = 2;
            while (BigInteger.GreatestCommonDivisor(e, phi) != BigInteger.One)
            {
                e++;
            }

            for (BigInteger i = 1; i < phi; i = BigInteger.Add(i, 1))
            {
                d = BigInteger.DivRem(BigInteger.Add(BigInteger.Multiply(i, phi), 1), e, out BigInteger remainder);
                if (remainder == 0)
                {
                    break;
                }
            }
        }

        public (BigInteger, BigInteger) PublicKey => (e, n);

        public (BigInteger, BigInteger) PrivateKey => (d, n);

        public List<BigInteger> Encrypt(string message)
        {
            var result = new List<BigInteger>();
            foreach (var ch in message)
            {
                var crypted = BigInteger.ModPow((BigInteger)ch, e, n);
                result.Add(crypted);
            }

            return result;
        }

        public string Decrypt(List<BigInteger> encryptrdMessage)
        {
            var result = new StringBuilder();
            foreach (var number in encryptrdMessage)
            {
                var ch = char.ConvertFromUtf32((int)BigInteger.ModPow(number, d, n));
                result.Append(ch);
            }

            return result.ToString();
        }
    }
}
