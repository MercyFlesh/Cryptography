using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace RSA
{
    public static class BigIntegerExtensions
    {
        public static BigInteger Mod(this BigInteger lvalue, BigInteger rvalue)
        {
            return (BigInteger.Abs(lvalue * rvalue) + lvalue) % rvalue;
        }

        public static bool IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1)
            {
                return false;
            }

            if (witnesses <= 0)
            {
                witnesses = 10;
            }

            var d = value - 1;
            var pow = 0;

            while ((d & 1) == 0)
            {
                d >>= 1;

                pow += 1;
            }

            var random = RandomNumberGenerator.Create();

            BigInteger a;
            for (var i = 0; i < witnesses; ++i)
            {
                do
                {
                    a = BigIntegerRandom(random);
                }
                while (a < 2 || a >= value - 2);

                var x = ModularExponentiation(a, d, value);

                if (x == 1 || x == value - 1)
                {
                    continue;
                }

                for (var r = 1; r < pow; ++r)
                {
                    x = ModularExponentiation(x, 2, value);

                    if (x == 1)
                    {
                        return false;
                    }

                    if (x == value - 1)
                    {
                        break;
                    }
                }

                if (x != value - 1)
                {
                    return false;
                }
            }

            return true;
        }

        public static BigInteger ModularExponentiation(BigInteger value, BigInteger exp, BigInteger mod)
        {

            if (mod == 1) return 0;

            value = Mod(value, mod);

            BigInteger result = 1;

            while (exp > 0)
            {
                if ((exp & 1) == 1)
                {
                    result = Mod(mod, (result * value));
                }

                exp >>= 1;

                value = Mod(mod, (value * value));
            }

            return result;
        }

        public static BigInteger BigIntegerRandom(this RandomNumberGenerator random)
        {
            var bytes = new byte[64];
            random.GetNonZeroBytes(bytes);
            return BitConverter.ToInt64(bytes);
        }
    }
}
