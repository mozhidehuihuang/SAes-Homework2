namespace SAesCore
{
    /// <summary>
    /// S-AES 密钥扩展（教材 D.3）：16 位初始密钥扩展为 6 个 8 位字 w0~w5，
    /// 组合成 3 个 16 位轮密钥 K0、K1、K2。
    /// </summary>
    public static class KeyExpansion
    {
        public const byte Rcon1 = 0x80; // 1000 0000
        public const byte Rcon2 = 0x30; // 0011 0000

        /// <summary>返回 6 个 8 位字 w0~w5。</summary>
        public static byte[] Words(ushort key)
        {
            byte[] words = new byte[6];
            words[0] = (byte)(key >> 8);        // w0
            words[1] = (byte)(key & 0x00FF);    // w1

            words[2] = (byte)(words[0] ^ G(words[1], Rcon1)); // w2
            words[3] = (byte)(words[2] ^ words[1]);          // w3
            words[4] = (byte)(words[2] ^ G(words[3], Rcon2)); // w4
            words[5] = (byte)(words[4] ^ words[3]);          // w5

            return words;
        }

        /// <summary>返回 3 个 16 位轮密钥：K0 = (w0,w1)，K1 = (w2,w3)，K2 = (w4,w5)。</summary>
        public static ushort[] Expand(ushort key)
        {
            byte[] words = Words(key);

            return new[]
            {
                (ushort)((words[0] << 8) | words[1]),
                (ushort)((words[2] << 8) | words[3]),
                (ushort)((words[4] << 8) | words[5])
            };
        }

        /// <summary>
        /// 密钥扩展中的 g 函数：RotNib（交换半字节）→ SubNib（S 盒替换）→ 与轮常数异或。
        /// 注意：轮常数低半字节为 0，因此只需对 RotNib 后字节的两个半字节做 S 盒替换。
        /// </summary>
        private static byte G(byte word, byte rcon)
        {
            byte rotated = SBoxTable.RotateNibbles(word);
            byte substituted = SBoxTable.SubNibbles(rotated);

            return (byte)(substituted ^ rcon);
        }
    }
}
