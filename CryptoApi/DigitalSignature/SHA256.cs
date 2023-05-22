using Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalSignature
{
    public class SHA256 : IHash
    {
        //При реализации алгоритма используется тип uint
        //для автоматического выполнения сложения по модулю 2^32

        //Таблица констант
        //(первые 32 бита дробных частей кубических корней первых 64 простых чисел 
        //[от 2 до 311]):
        private readonly List<uint> tableK = new () {
           0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
           0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
           0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
           0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
           0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
           0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
           0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
           0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
           0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
           0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
           0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
           0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
           0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
           0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
           0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
           0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        private List<uint> vectorH = new();

        public string GetHash(string text)
        {
            //Инициализация переменных
            //(первые 32 бита дробных частей квадратных корней первых восьми простых чисел
            //[от 2 до 19]):
            vectorH = new List<uint>()
            {
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
            };

            var bits = GetBits(text);

            string message = null;

            if (bits.Count > 0)
            {
                message = bits.Aggregate((a, b) => a + b);
            }
            else
            {
                message = "";
            }

            var msgLength = (ulong)message.LongCount();

            //добавить логическую единицу
            message += "1";

            //добавлять логические нули
            //пока размер не сравним с 448 по модулю 512
            do
            {
                message += "0";
            } while (message.Length % 512 != 448);


            //получить двоичное представление длины сообщения
            var msgLengthBinary = Convert
                                    .ToString((long)msgLength, 2)
                                    .PadLeft(64, '0');

            message += msgLengthBinary;

            //разбить сообщение Т на блоки по 512 бит
            var blocks = SplitMessage(message, 512);

            foreach (var block in blocks)
            {
                //разбить блок на 16 DWORD'ов
                //преобразовать из бинарной строки в uint
                var W = SplitMessage(block, 32)
                            .Select(value => Convert.ToUInt32(value, 2))
                            .ToList();


                for (var index = 16; index < 64; ++index)
                {
                    if (index <= W.Count - 1)
                    {
                        W[index] = W[index - 16] + S0(W[index - 15]) + W[index - 7] + S1(W[index - 2]);
                    }
                    //иначе начать расширение 
                    else
                    {
                        W.Add(W[index - 16] + S0(W[index - 15]) + W[index - 7] + S1(W[index - 2]));
                    }

                }
                //инициализировать значения a,b,c,d,f,g,h значениями вектора H
                var a = vectorH[0]; var b = vectorH[1];
                var c = vectorH[2]; var d = vectorH[3];
                var e = vectorH[4]; var f = vectorH[5];
                var g = vectorH[6]; var h = vectorH[7];

                //начать обработку
                for (var index = 0; index < 64; ++index)
                {
                    var t1 = h + Sigma1(e) + Ch(e, f, g) + tableK[index] + W[index];
                    var t2 = Sigma0(a) + Maj(a, b, c);

                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                //прибавить к исходным значениям вектора H
                //обработанные значения a,b,c,d,f,g,h
                vectorH[0] += a; vectorH[1] += b; vectorH[2] += c; vectorH[3] += d;
                vectorH[4] += e; vectorH[5] += f; vectorH[6] += g; vectorH[7] += h;

            }

            var stringBuilder = new StringBuilder();

            for (var index = 0; index < 8; ++index)
            {
                stringBuilder.Append(vectorH[index].ToString("X8"));
            }

            return stringBuilder.ToString();

        }

        //получить битовое представление строки
        //Перевести входные данные в UTF - 8
        private List<string> GetBits(string input)
        {

            var result = new List<string>();

            foreach (var value in Encoding.UTF8.GetBytes(input))
            {
                result.Add(Convert.ToString(value, 2).PadLeft(8, '0'));
            }

            return result;
        }

        private uint Sigma1(uint e)
        {
            return RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
        }

        private uint Sigma0(uint a)
        {
            return RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
        }

        private uint RotateRight(uint value, int shift)
        {
            return ((value >> shift) | (value << (32 - shift)));
        }

        private uint Ch(uint e, uint f, uint g)
        {
            return (e & f) ^ ((~e) & g);
        }

        private uint Maj(uint a, uint b, uint c)
        {
            return (a & b) ^ (a & c) ^ (b & c);
        }

        private uint S0(uint wi)
        {
            return RotateRight(wi, 7) ^ RotateRight(wi, 18) ^ (wi >> 3);
        }

        private uint S1(uint wi)
        {
            return RotateRight(wi, 17) ^ RotateRight(wi, 19) ^ (wi >> 10);
        }


        private IEnumerable<string> SplitMessage(string str, int maxLength)
        {
            for (int index = 0; index < str.Length; index += maxLength)
            {
                yield return str.Substring(index, Math.Min(maxLength, str.Length - index));
            }
        }
    }
}
