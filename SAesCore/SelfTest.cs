using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAesCore
{
    /// <summary>
    /// 内置自检：覆盖 5 个关卡的核心功能，供 GUI“自检”页和控制台测试程序使用。
    /// </summary>
    public static class SelfTest
    {
        /// <summary>运行全部自检，返回可直接显示的文本报告。</summary>
        public static string Run()
        {
            StringBuilder report = new StringBuilder();
            int passed = 0;
            int failed = 0;

            report.AppendLine("========== S-AES 程序自检报告 ==========");
            report.AppendLine();

            void Check(string title, bool ok, string detail = "")
            {
                if (ok)
                {
                    passed++;
                    report.AppendLine("[通过] " + title);
                }
                else
                {
                    failed++;
                    report.AppendLine("[失败] " + title);
                }

                if (!string.IsNullOrEmpty(detail))
                {
                    foreach (string line in detail.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        report.AppendLine("       " + line);
                    }
                }
            }

            // 1. 密钥扩展（教材 D.3 的例子：2D55 → w2=BC, w3=E9, w4=A3, w5=4A）
            ushort[] roundKeys = KeyExpansion.Expand(0x2D55);
            bool keyExpansionOk = roundKeys[0] == 0x2D55 && roundKeys[1] == 0xBCE9 && roundKeys[2] == 0xA34A;
            Check("密钥扩展：密钥 2D55 得到 K0/K1/K2", keyExpansionOk,
                string.Format("K0={0:X4}  K1={1:X4}  K2={2:X4}（期望 2D55 / BCE9 / A34A）",
                    roundKeys[0], roundKeys[1], roundKeys[2]));

            // 2. GF(2^4) 乘法（对照教材附件 D.1 的乘法表抽查）
            bool gfOk = Gf16.Multiply(0x4, 0xC) == 0x5
                        && Gf16.Multiply(0x9, 0x4) == 0x2
                        && Gf16.Multiply(0x2, 0x4) == 0x8
                        && Gf16.Multiply(0x9, 0x2) == 0x1;
            Check("GF(2^4) 乘法抽查（4·C=5，9·4=2，2·4=8，9·2=1）", gfOk);

            // 3. 基本加解密往返（第 1、2 关）
            Random random = new Random(2026);
            bool roundTripOk = true;
            for (int i = 0; i < 2000; i++)
            {
                ushort plaintext = (ushort)random.Next(0, 0x10000);
                ushort key = (ushort)random.Next(0, 0x10000);
                ushort ciphertext = SAes.Encrypt(plaintext, key);
                if (SAes.Decrypt(ciphertext, key) != plaintext)
                {
                    roundTripOk = false;
                    report.AppendLine(string.Format("       失败样例：P={0:X4} K={1:X4} C={2:X4}", plaintext, key, ciphertext));
                    break;
                }
            }

            Check("基本加解密：2000 组随机明文/密钥加解密往返一致", roundTripOk);

            // 4. 公开测试向量（S-AES 经典示例：密钥 4AF5，明文 D728，密文 24EC）
            ushort vectorCipher = SAes.Encrypt(0xD728, 0x4AF5);
            bool vectorOk = vectorCipher == 0x24EC && SAes.Decrypt(0x24EC, 0x4AF5) == 0xD728;
            Check("测试向量：密钥 4AF5 加密明文 D728", vectorOk,
                string.Format("得到密文 {0:X4}（期望 24EC）", vectorCipher));

            // 5. 第 3 关：字符串（2 字节一组）加解密
            string sampleText = "S-AES 信息安全导论";
            byte[] bytes = BlockStringCipher.ToBytes(sampleText);
            ushort[] blocks = BlockStringCipher.EncryptBytes(bytes, 0x2D55);
            byte[] restored = BlockStringCipher.DecryptBlocks(blocks, 0x2D55);
            bool stringOk = restored.Length >= bytes.Length &&
                            bytes.SequenceEqual(restored.Take(bytes.Length));
            Check("字符串模式：UTF-8 文本按 2 字节分组加解密往返", stringOk,
                "明文：" + sampleText + "，分组：" + BlockStringCipher.ToHex(blocks));

            // 6. 双重加密（第 4.1 关）
            ushort doubleCipher = MultipleEncryption.DoubleEncrypt(0x6F6B, 0x2D55, 0x55AA);
            bool doubleOk = MultipleEncryption.DoubleDecrypt(doubleCipher, 0x2D55, 0x55AA) == 0x6F6B;
            Check("双重加密往返（K1=2D55，K2=55AA）", doubleOk,
                string.Format("密文 {0:X4}", doubleCipher));

            // 7. 中间相遇攻击（第 4.2 关）
            List<KnownPair> pairs = new List<KnownPair>();
            foreach (ushort plaintext in new ushort[] { 0x6F6B, 0x1234, 0xA5C3 })
            {
                pairs.Add(new KnownPair(plaintext, MultipleEncryption.DoubleEncrypt(plaintext, 0x2D55, 0x55AA)));
            }

            MeetInTheMiddleResult attack = MeetInTheMiddle.Attack(pairs);
            bool attackOk = attack.Success && attack.Key1 == 0x2D55 && attack.Key2 == 0x55AA && attack.ValidKeyPairCount == 1;
            Check("中间相遇攻击恢复密钥（目标 K1=2D55，K2=55AA）", attackOk,
                string.Format("恢复 K1={0:X4}，K2={1:X4}；有效密钥组合 {2} 个；耗时 {3} ms；使用 {4} 组明密文对",
                    attack.Key1, attack.Key2, attack.ValidKeyPairCount, attack.ElapsedMilliseconds, attack.PairCount));

            // 8. 三重加密（第 4.3 关，两种模式）
            ushort triple32 = MultipleEncryption.TripleEncrypt(0x6F6B, 0x2D55, 0x55AA);
            bool triple32Ok = MultipleEncryption.TripleDecrypt(triple32, 0x2D55, 0x55AA) == 0x6F6B;

            ushort triple48 = MultipleEncryption.TripleEncrypt(0x6F6B, 0x2D55, 0x55AA, 0x1234);
            bool triple48Ok = MultipleEncryption.TripleDecrypt(triple48, 0x2D55, 0x55AA, 0x1234) == 0x6F6B;

            Check("三重加密往返（32 位密钥模式 K1/K2/K1）", triple32Ok, string.Format("密文 {0:X4}", triple32));
            Check("三重加密往返（48 位密钥模式 K1/K2/K3）", triple48Ok, string.Format("密文 {0:X4}", triple48));

            // 9. CBC 模式与篡改演示（第 5 关）
            byte[] cbcPlain = BlockStringCipher.ToBytes("CBC 模式演示：信息安全导论 S-AES。");
            ushort[] cbcCipher = CbcMode.Encrypt(cbcPlain, 0x2D55, 0xA5A5);
            byte[] cbcRestored = CbcMode.Decrypt(cbcCipher, 0x2D55, 0xA5A5);
            bool cbcOk = cbcPlain.SequenceEqual(cbcRestored.Take(cbcPlain.Length));
            Check("CBC 工作模式：多分组往返一致", cbcOk,
                "密文：" + BlockStringCipher.ToHex(cbcCipher) + "；IV=A5A5");

            ushort[] tampered = (ushort[])cbcCipher.Clone();
            tampered[0] ^= 0x0100; // 修改第一个密文分组的最高字节
            byte[] tamperedPlain = CbcMode.Decrypt(tampered, 0x2D55, 0xA5A5);
            string difference = CbcMode.DescribeBlockDifferences(cbcRestored, tamperedPlain);
            bool tamperOk = !cbcRestored.SequenceEqual(tamperedPlain);
            Check("CBC 篡改密文：修改第 1 个密文分组后解密结果发生变化", tamperOk, difference.TrimEnd());

            report.AppendLine();
            report.AppendLine(string.Format("总计：{0} 项通过，{1} 项失败。", passed, failed));
            report.AppendLine(failed == 0 ? "结论：全部自检通过。" : "结论：存在失败项，请检查实现。");

            return report.ToString();
        }
    }
}
