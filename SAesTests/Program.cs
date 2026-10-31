using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SAesCore;

namespace SAesTests
{
    /// <summary>
    /// 控制台测试程序：输出 5 个关卡的测试结果，便于保留测试记录（也可在 GUI 的“自检”页查看）。
    /// </summary>
    internal static class Program
    {
        private static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine(SelfTest.Run());
            Console.WriteLine();

            PrintBasicVectors();
            PrintStringDemo();
            PrintMitmDemo();
            PrintCbcDemo();
        }

        /// <summary>第 1、2 关：一组标准测试向量（同密钥、同明文，加密结果一致）。</summary>
        private static void PrintBasicVectors()
        {
            Console.WriteLine("========== 第 1/2 关：基本测试向量 ==========");
            Console.WriteLine("密钥     明文     密文     解密还原   结果");
            ushort[] keys = { 0x0000, 0x2D55, 0xA73A, 0xFFFF };
            ushort[] plaintexts = { 0x0000, 0x6F6B, 0x1234, 0xA5C3 };

            foreach (ushort key in keys)
            {
                foreach (ushort plaintext in plaintexts)
                {
                    ushort ciphertext = SAes.Encrypt(plaintext, key);
                    ushort restored = SAes.Decrypt(ciphertext, key);
                    Console.WriteLine("{0,-8:X4} {1,-8:X4} {2,-8:X4} {3,-10:X4} {4}",
                        key, plaintext, ciphertext, restored, restored == plaintext ? "通过" : "失败");
                }
            }

            Console.WriteLine();
        }

        /// <summary>第 3 关：ASCII/UTF-8 字符串按 2 字节分组加解密。</summary>
        private static void PrintStringDemo()
        {
            Console.WriteLine("========== 第 3 关：字符串扩展 ==========");
            string text = "Information Security S-AES";
            byte[] bytes = BlockStringCipher.ToBytes(text);
            ushort[] blocks = BlockStringCipher.EncryptBytes(bytes, 0x2D55);
            byte[] restored = BlockStringCipher.DecryptBlocks(blocks, 0x2D55);

            Console.WriteLine("明文：" + text);
            Console.WriteLine("密文分组：" + BlockStringCipher.ToHex(blocks));
            Console.WriteLine("密文字符：" + BlockStringCipher.EscapeBytes(BlockStringCipher.BlocksToBytes(blocks), false));
            Console.WriteLine("解密还原：" + Encoding.UTF8.GetString(restored).TrimEnd('\0'));
            Console.WriteLine("还原一致：" + bytes.SequenceEqual(restored.Take(bytes.Length)));
            Console.WriteLine();
        }

        /// <summary>第 4.2 关：中间相遇攻击，展示 1 组与 3 组明密文对下的候选数量。</summary>
        private static void PrintMitmDemo()
        {
            Console.WriteLine("========== 第 4.2 关：中间相遇攻击 ==========");
            const ushort expectedKey1 = 0x2D55;
            const ushort expectedKey2 = 0x55AA;

            List<KnownPair> allPairs = new List<KnownPair>();
            foreach (ushort plaintext in new ushort[] { 0x6F6B, 0x1234, 0xA5C3, 0xFFFF })
            {
                allPairs.Add(new KnownPair(plaintext, MultipleEncryption.DoubleEncrypt(plaintext, expectedKey1, expectedKey2)));
            }

            foreach (int count in new[] { 1, 2, 3 })
            {
                MeetInTheMiddleResult result = MeetInTheMiddle.Attack(allPairs.Take(count).ToList());
                Console.WriteLine("使用 {0} 组明密文：K1={1:X4}  K2={2:X4}  候选 {3} 个  耗时 {4} ms  验证 {5}",
                    count, result.Key1, result.Key2, result.ValidKeyPairCount, result.ElapsedMilliseconds,
                    result.Success ? "通过" : "失败");
            }

            Console.WriteLine();
        }

        /// <summary>第 5 关：CBC 工作模式与篡改演示。</summary>
        private static void PrintCbcDemo()
        {
            Console.WriteLine("========== 第 5 关：CBC 工作模式 ==========");
            const ushort key = 0x2D55;
            const ushort iv = 0xA5A5;
            string text = "信息安全导论 CBC 工作模式演示：这是一条较长的明文消息，分为多个 16 位分组。";

            byte[] plainBytes = BlockStringCipher.ToBytes(text);
            ushort[] cipherBlocks = CbcMode.Encrypt(plainBytes, key, iv);

            Console.WriteLine("密钥=" + key.ToString("X4") + "  IV=" + iv.ToString("X4") +
                              "  分组数=" + cipherBlocks.Length);
            Console.WriteLine("明文：" + text);
            Console.WriteLine("密文：" + BlockStringCipher.ToHex(cipherBlocks));

            byte[] restored = CbcMode.Decrypt(cipherBlocks, key, iv);
            Console.WriteLine("解密：" + Encoding.UTF8.GetString(restored).TrimEnd('\0'));
            Console.WriteLine();

            ushort[] tamperedBlocks = (ushort[])cipherBlocks.Clone();
            tamperedBlocks[0] ^= 0x0100;
            Console.WriteLine("篡改操作：翻转第 1 个密文分组的最高字节最低位（C1: " +
                              cipherBlocks[0].ToString("X4") + " → " + tamperedBlocks[0].ToString("X4") + "）");
            Console.WriteLine("篡改后密文：" + BlockStringCipher.ToHex(tamperedBlocks));

            byte[] tamperedPlain = CbcMode.Decrypt(tamperedBlocks, key, iv);
            Console.WriteLine("篡改后解密：" + Encoding.UTF8.GetString(tamperedPlain).TrimEnd('\0'));
            Console.WriteLine("逐块差异（前 3 块）：");
            foreach (string line in CbcMode.DescribeBlockDifferences(restored, tamperedPlain)
                         .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Take(3))
            {
                Console.WriteLine(line);
            }

            Console.WriteLine("结论：第 1 块解密结果随机改变，第 2 块出现 1 位翻转，之后的分组不受影响。");
        }
    }
}
