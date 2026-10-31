namespace SAesCore
{
    /// <summary>
    /// GF(2^4) 上的运算：加法为按位异或，乘法模不可约多项式 x^4 + x + 1（0b10011，即 0x13）。
    /// 教材附件 D.1 中的加法表、乘法表均由该定义生成。
    /// </summary>
    public static class Gf16
    {
        /// <summary>GF(2^4) 加法，等价于按位异或。</summary>
        public static byte Add(byte left, byte right) => (byte)((left ^ right) & 0x0F);

        /// <summary>GF(2^4) 乘法（模 x^4 + x + 1），采用移位相加的“农夫乘法”。</summary>
        public static byte Multiply(byte left, byte right)
        {
            int multiplicand = left & 0x0F;
            int multiplier = right & 0x0F;
            int product = 0;

            while (multiplier > 0)
            {
                if ((multiplier & 1) == 1)
                {
                    product ^= multiplicand;
                }

                multiplier >>= 1;
                multiplicand <<= 1;

                // 若超出 4 位，则模 x^4 + x + 1（0x13）约简
                if ((multiplicand & 0x10) != 0)
                {
                    multiplicand ^= 0x13;
                }
            }

            return (byte)(product & 0x0F);
        }

        /// <summary>GF(2^4) 求乘法逆元，0 的逆元按惯例返回 0。</summary>
        public static byte Inverse(byte value)
        {
            value &= 0x0F;
            if (value == 0)
            {
                return 0;
            }

            for (byte candidate = 1; candidate <= 0x0F; candidate++)
            {
                if (Multiply(value, candidate) == 1)
                {
                    return candidate;
                }
            }

            return 0;
        }
    }
}
