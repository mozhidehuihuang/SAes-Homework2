namespace SAesCore
{
    /// <summary>
    /// 多重加密（第 4 关）：
    /// 1) 双重加密：C = E_K2(E_K1(P))，密钥 32 位（K1‖K2）；
    /// 2) 三重加密（32 位密钥模式）：C = E_K1(E_K2(E_K1(P)))，密钥 32 位（K1‖K2）；
    /// 3) 三重加密（48 位密钥模式）：C = E_K3(E_K2(E_K1(P)))，密钥 48 位（K1‖K2‖K3）。
    /// </summary>
    public static class MultipleEncryption
    {
        /// <summary>双重加密。</summary>
        public static ushort DoubleEncrypt(ushort plaintext, ushort key1, ushort key2)
            => SAes.Encrypt(SAes.Encrypt(plaintext, key1), key2);

        /// <summary>双重解密。</summary>
        public static ushort DoubleDecrypt(ushort ciphertext, ushort key1, ushort key2)
            => SAes.Decrypt(SAes.Decrypt(ciphertext, key2), key1);

        /// <summary>三重加密，32 位密钥模式（K1、K2、K1）。</summary>
        public static ushort TripleEncrypt(ushort plaintext, ushort key1, ushort key2)
            => SAes.Encrypt(SAes.Encrypt(SAes.Encrypt(plaintext, key1), key2), key1);

        /// <summary>三重解密，32 位密钥模式（K1、K2、K1）。</summary>
        public static ushort TripleDecrypt(ushort ciphertext, ushort key1, ushort key2)
            => SAes.Decrypt(SAes.Decrypt(SAes.Decrypt(ciphertext, key1), key2), key1);

        /// <summary>三重加密，48 位密钥模式（K1、K2、K3）。</summary>
        public static ushort TripleEncrypt(ushort plaintext, ushort key1, ushort key2, ushort key3)
            => SAes.Encrypt(SAes.Encrypt(SAes.Encrypt(plaintext, key1), key2), key3);

        /// <summary>三重解密，48 位密钥模式（K1、K2、K3）。</summary>
        public static ushort TripleDecrypt(ushort ciphertext, ushort key1, ushort key2, ushort key3)
            => SAes.Decrypt(SAes.Decrypt(SAes.Decrypt(ciphertext, key3), key2), key1);
    }
}
