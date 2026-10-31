using System;
using System.Text;

namespace SAesCore
{
    /// <summary>
    /// 第 5 关：密码分组链接（CBC）工作模式。
    /// 加密：C_i = E_K(P_i ⊕ C_(i-1))，其中 C_0 = IV；
    /// 解密：P_i = D_K(C_i) ⊕ C_(i-1)。
    /// 分组长度 16 位，初始向量 IV 为 16 位，需由加解密双方共享。
    /// </summary>
    public static class CbcMode
    {
        /// <summary>对字节串做 CBC 加密；奇数长度时末尾补 0x00，返回 16 位密文分组。</summary>
        public static ushort[] Encrypt(byte[] plainBytes, ushort key, ushort iv)
        {
            byte[] padded = BlockStringCipher.PadToEvenLength(plainBytes);
            ushort[] cipherBlocks = new ushort[padded.Length / 2];
            ushort previous = iv;

            for (int i = 0; i < cipherBlocks.Length; i++)
            {
                ushort plainBlock = (ushort)((padded[2 * i] << 8) | padded[2 * i + 1]);
                ushort chained = (ushort)(plainBlock ^ previous); // 与前一分组密文（或 IV）异或
                ushort encrypted = SAes.Encrypt(chained, key);

                cipherBlocks[i] = encrypted;
                previous = encrypted;
            }

            return cipherBlocks;
        }

        /// <summary>对 CBC 密文分组解密，返回字节串。</summary>
        public static byte[] Decrypt(ushort[] cipherBlocks, ushort key, ushort iv)
        {
            if (cipherBlocks == null)
            {
                throw new ArgumentNullException(nameof(cipherBlocks));
            }

            byte[] plainBytes = new byte[cipherBlocks.Length * 2];
            ushort previous = iv;

            for (int i = 0; i < cipherBlocks.Length; i++)
            {
                ushort decrypted = SAes.Decrypt(cipherBlocks[i], key);
                ushort plainBlock = (ushort)(decrypted ^ previous);

                plainBytes[2 * i] = (byte)(plainBlock >> 8);
                plainBytes[2 * i + 1] = (byte)(plainBlock & 0x00FF);
                previous = cipherBlocks[i];
            }

            return plainBytes;
        }

        /// <summary>
        /// 统计两组解密结果在每一个 16 位分组上的差异，用于演示篡改密文后的影响：
        /// 被修改的分组解密后完全乱码，其后一个分组出现对应比特翻转，再往后的分组不受影响。
        /// </summary>
        public static string DescribeBlockDifferences(byte[] baseline, byte[] modified)
        {
            int blockCount = Math.Min(baseline.Length, modified.Length) / 2;
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < blockCount; i++)
            {
                int differingBytes = 0;
                int differingBits = 0;

                for (int j = 0; j < 2; j++)
                {
                    int index = 2 * i + j;
                    byte difference = (byte)(baseline[index] ^ modified[index]);
                    if (difference != 0)
                    {
                        differingBytes++;
                        differingBits += CountBits(difference);
                    }
                }

                string conclusion;
                if (differingBytes == 0)
                {
                    conclusion = "无变化";
                }
                else if (differingBytes == 2)
                {
                    conclusion = "整块随机改变（雪崩效应）";
                }
                else if (differingBits == 1)
                {
                    conclusion = "单比特翻转（CBC 比特传播）";
                }
                else
                {
                    conclusion = "部分比特改变";
                }

                builder.AppendFormat("第 {0} 块：{1}/2 字节不同，共 {2} 位翻转 → {3}\r\n",
                    i + 1, differingBytes, differingBits, conclusion);
            }

            if (baseline.Length != modified.Length)
            {
                builder.AppendLine("注意：两组数据长度不一致。");
            }

            return builder.ToString();
        }

        private static int CountBits(byte value)
        {
            int count = 0;
            while (value != 0)
            {
                count += value & 1;
                value >>= 1;
            }

            return count;
        }
    }
}
