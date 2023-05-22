using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Interfaces
{
    public interface ICryptor
    {
        List<BigInteger> Encrypt(string message);
        string Decrypt(List<BigInteger> encryptrdMessage);
    }
}
