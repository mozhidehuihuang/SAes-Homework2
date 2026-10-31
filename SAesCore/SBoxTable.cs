namespace SAesCore
{
    /// <summary>
    /// S-AES 的 4 位 S 盒（教材表 D.1(a)）及其逆盒（表 D.1(b)）。
    /// 行、列均为 0~3（对应半字节高 2 位与低 2 位），表项为十六进制值。
    /// </summary>
    public static class SBoxTable
    {
        // 正向 S 盒：S(0x0)=0x9, S(0x5)=0x1 ... S(0xF)=0x7
        private static readonly byte[] SBox =
        {
            0x9, 0x4, 0xA, 0xB,
            0xD, 0x1, 0x8, 0x5,
            0x6, 0x2, 0x0, 0x3,
            0xC, 0xE, 0xF, 0x7
        };

        // 逆 S 盒：InvS(0x0)=0xA ... InvS(0xF)=0xE
        private static readonly byte[] InvSBox =
        {
            0xA, 0x5, 0x9, 0xB,
            0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3,
            0xC, 0x4, 0xD, 0xE
        };

        /// <summary>对单个 4 位半字节做 S 盒替换。</summary>
        public static byte SubNibble(byte nibble) => SBox[nibble & 0x0F];

        /// <summary>对单个 4 位半字节做逆 S 盒替换。</summary>
        public static byte InvSubNibble(byte nibble) => InvSBox[nibble & 0x0F];

        /// <summary>对一个字节（两个半字节）分别做 S 盒替换。</summary>
        public static byte SubNibbles(byte value)
            => (byte)((SubNibble((byte)(value >> 4)) << 4) | SubNibble((byte)(value & 0x0F)));

        /// <summary>对一个字节（两个半字节）分别做逆 S 盒替换。</summary>
        public static byte InvSubNibbles(byte value)
            => (byte)((InvSubNibble((byte)(value >> 4)) << 4) | InvSubNibble((byte)(value & 0x0F)));

        /// <summary>交换字节中的高、低半字节（密钥扩展 g 函数中的 RotNib）。</summary>
        public static byte RotateNibbles(byte value)
            => (byte)(((value & 0x0F) << 4) | ((value & 0xF0) >> 4));
    }
}
