using System.Collections.Generic;
using System.Diagnostics;

namespace SAesCore
{
    /// <summary>一组已知的 16 位明密文对。</summary>
    public sealed class KnownPair
    {
        public KnownPair(ushort plaintext, ushort ciphertext)
        {
            Plaintext = plaintext;
            Ciphertext = ciphertext;
        }

        public ushort Plaintext { get; }

        public ushort Ciphertext { get; }
    }

    /// <summary>中间相遇攻击的结果。</summary>
    public sealed class MeetInTheMiddleResult
    {
        public bool Success { get; set; }

        public ushort Key1 { get; set; }

        public ushort Key2 { get; set; }

        /// <summary>能与全部已知明密文对吻合的密钥组合数量（用于证明唯一性）。</summary>
        public int ValidKeyPairCount { get; set; }

        public long ElapsedMilliseconds { get; set; }

        public int PairCount { get; set; }
    }

    /// <summary>
    /// 中间相遇攻击（第 4.2 关）：针对双重加密 C = E_K2(E_K1(P))。
    /// 思路：用第一组明密文建表 mid = E_K1(P0)，再遍历 K2 计算 mid = D_K2(C0)，
    /// 命中的 (K1,K2) 用其余明密文对逐一验证。时间复杂度约 2 × 2^16，空间 2^16。
    /// </summary>
    public static class MeetInTheMiddle
    {
        public static MeetInTheMiddleResult Attack(IList<KnownPair> pairs)
        {
            if (pairs == null || pairs.Count == 0)
            {
                throw new System.ArgumentException("至少需要一组已知明密文对。", nameof(pairs));
            }

            Stopwatch stopwatch = Stopwatch.StartNew();

            KnownPair reference = pairs[0];

            // 第一步：对全部 2^16 个 K1 计算中间值，并按中间值建立索引表
            Dictionary<ushort, List<ushort>> middleTable = new Dictionary<ushort, List<ushort>>(0x10000);
            for (int key1 = 0; key1 <= 0xFFFF; key1++)
            {
                ushort middle = SAes.Encrypt(reference.Plaintext, (ushort)key1);
                if (!middleTable.TryGetValue(middle, out List<ushort> keys))
                {
                    keys = new List<ushort>(1);
                    middleTable.Add(middle, keys);
                }

                keys.Add((ushort)key1);
            }

            // 第二步：遍历 K2，反向解密第一组密文，查表寻找匹配的中间值
            List<MeetInTheMiddleResult> matches = new List<MeetInTheMiddleResult>();
            for (int key2 = 0; key2 <= 0xFFFF; key2++)
            {
                ushort middle = SAes.Decrypt(reference.Ciphertext, (ushort)key2);
                if (!middleTable.TryGetValue(middle, out List<ushort> candidateKey1List))
                {
                    continue;
                }

                foreach (ushort candidateKey1 in candidateKey1List)
                {
                    if (VerifyAllPairs(pairs, candidateKey1, (ushort)key2))
                    {
                        matches.Add(new MeetInTheMiddleResult
                        {
                            Success = true,
                            Key1 = candidateKey1,
                            Key2 = (ushort)key2,
                            ValidKeyPairCount = 1,
                            PairCount = pairs.Count
                        });
                    }
                }
            }

            stopwatch.Stop();

            MeetInTheMiddleResult result;
            if (matches.Count == 0)
            {
                result = new MeetInTheMiddleResult
                {
                    Success = false,
                    ValidKeyPairCount = 0,
                    PairCount = pairs.Count
                };
            }
            else
            {
                result = matches[0];
                result.ValidKeyPairCount = matches.Count;
                result.PairCount = pairs.Count;
            }

            result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            return result;
        }

        private static bool VerifyAllPairs(IList<KnownPair> pairs, ushort key1, ushort key2)
        {
            ushort[] roundKeys1 = KeyExpansion.Expand(key1);
            ushort[] roundKeys2 = KeyExpansion.Expand(key2);

            for (int i = 0; i < pairs.Count; i++)
            {
                KnownPair pair = pairs[i];
                ushort encrypted = SAes.Encrypt(SAes.Encrypt(pair.Plaintext, roundKeys1), roundKeys2);
                if (encrypted != pair.Ciphertext)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
