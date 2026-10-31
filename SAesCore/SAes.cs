using System.Collections.Generic;

namespace SAesCore
{
    /// <summary>算法单步执行记录，用于 GUI 展示加密/解密过程。</summary>
    public sealed class StepTrace
    {
        public StepTrace(string name, ushort state)
        {
            Name = name;
            State = state;
        }

        public string Name { get; }

        public ushort State { get; }

        /// <summary>16 位状态的十六进制文本，例如 "6F6B"。</summary>
        public string StateHex => State.ToString("X4");

        public override string ToString() => Name.PadRight(26) + StateHex;
    }

    /// <summary>
    /// S-AES 分组密码（教材附录 D）。分组长度 16 位，密钥长度 16 位。
    /// 加密：AK0 → (NS · SR · MC · AK1) → (NS · SR · AK2)
    /// </summary>
    public static class SAes
    {
        /// <summary>用 16 位密钥加密 16 位明文。</summary>
        public static ushort Encrypt(ushort plaintext, ushort key)
            => Encrypt(plaintext, KeyExpansion.Expand(key));

        /// <summary>用 16 位密钥解密 16 位密文。</summary>
        public static ushort Decrypt(ushort ciphertext, ushort key)
            => Decrypt(ciphertext, KeyExpansion.Expand(key));

        /// <summary>使用预先扩展好的 3 个轮加密 16 位明文。</summary>
        public static ushort Encrypt(ushort plaintext, ushort[] roundKeys)
        {
            ValidateRoundKeys(roundKeys);

            // 初始密钥加
            ushort state = AddRoundKey(plaintext, roundKeys[0]);

            // 第 1 轮（完整轮）：半字节代替、行位移、列混淆、轮密钥加
            state = SubNibbles(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoundKey(state, roundKeys[1]);

            // 第 2 轮（没有列混淆）：半字节代替、行位移、轮密钥加
            state = SubNibbles(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, roundKeys[2]);

            return state;
        }

        /// <summary>使用预先扩展好的 3 个轮密钥解密 16 位密文。</summary>
        public static ushort Decrypt(ushort ciphertext, ushort[] roundKeys)
        {
            ValidateRoundKeys(roundKeys);

            // 逆过程按加密步骤的严格逆序执行
            ushort state = AddRoundKey(ciphertext, roundKeys[2]);

            // 第 2 轮的逆：逆半字节代替、逆行位移
            state = InvSubNibbles(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, roundKeys[1]);

            // 第 1 轮的逆：逆列混淆、逆行位移、逆半字节代替
            state = InvMixColumns(state);
            state = InvSubNibbles(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, roundKeys[0]);

            return state;
        }

        /// <summary>记录加密的每一步中间状态。</summary>
        public static List<StepTrace> EncryptTrace(ushort plaintext, ushort key)
        {
            ushort[] keys = KeyExpansion.Expand(key);
            List<StepTrace> trace = new List<StepTrace> { new StepTrace("明文", plaintext) };

            ushort state = AddRoundKey(plaintext, keys[0]);
            trace.Add(new StepTrace("初始密钥加 AK0", state));

            state = SubNibbles(state);
            trace.Add(new StepTrace("第1轮 半字节代替 NS", state));

            state = ShiftRows(state);
            trace.Add(new StepTrace("第1轮 行位移 SR", state));

            state = MixColumns(state);
            trace.Add(new StepTrace("第1轮 列混淆 MC", state));

            state = AddRoundKey(state, keys[1]);
            trace.Add(new StepTrace("第1轮 轮密钥加 AK1", state));

            state = SubNibbles(state);
            trace.Add(new StepTrace("第2轮 半字节代替 NS", state));

            state = ShiftRows(state);
            trace.Add(new StepTrace("第2轮 行位移 SR", state));

            state = AddRoundKey(state, keys[2]);
            trace.Add(new StepTrace("第2轮 轮密钥加 AK2", state));

            trace.Add(new StepTrace("密文", state));
            return trace;
        }

        /// <summary>记录解密的每一步中间状态。</summary>
        public static List<StepTrace> DecryptTrace(ushort ciphertext, ushort key)
        {
            ushort[] keys = KeyExpansion.Expand(key);
            List<StepTrace> trace = new List<StepTrace> { new StepTrace("密文", ciphertext) };

            ushort state = AddRoundKey(ciphertext, keys[2]);
            trace.Add(new StepTrace("轮密钥加 AK2", state));

            state = InvSubNibbles(state);
            trace.Add(new StepTrace("逆半字节代替 INS", state));

            state = ShiftRows(state);
            trace.Add(new StepTrace("逆行位移 ISR", state));

            state = AddRoundKey(state, keys[1]);
            trace.Add(new StepTrace("轮密钥加 AK1", state));

            state = InvMixColumns(state);
            trace.Add(new StepTrace("逆列混淆 IMC", state));

            state = InvSubNibbles(state);
            trace.Add(new StepTrace("逆半字节代替 INS", state));

            state = ShiftRows(state);
            trace.Add(new StepTrace("逆行位移 ISR", state));

            state = AddRoundKey(state, keys[0]);
            trace.Add(new StepTrace("轮密钥加 AK0", state));

            trace.Add(new StepTrace("明文", state));
            return trace;
        }

        // ---------- 轮函数 ----------

        /// <summary>轮密钥加：16 位状态与 16 位轮密钥按位异或（其自身即逆运算）。</summary>
        public static ushort AddRoundKey(ushort state, ushort roundKey) => (ushort)(state ^ roundKey);

        /// <summary>半字节代替：对 4 个半字节分别查 S 盒。</summary>
        public static ushort SubNibbles(ushort state)
            => (ushort)((SBoxTable.SubNibbles((byte)(state >> 8)) << 8) |
                        SBoxTable.SubNibbles((byte)(state & 0x00FF)));

        /// <summary>逆半字节代替：对 4 个半字节分别查逆 S 盒。</summary>
        public static ushort InvSubNibbles(ushort state)
            => (ushort)((SBoxTable.InvSubNibbles((byte)(state >> 8)) << 8) |
                        SBoxTable.InvSubNibbles((byte)(state & 0x00FF)));

        /// <summary>
        /// 行位移：状态第二行（s10、s11）循环左移一个半字节，即交换第 2、4 个半字节。
        /// 该变换与其逆变换相同。
        /// </summary>
        public static ushort ShiftRows(ushort state)
            => (ushort)((state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8));

        /// <summary>
        /// 列混淆：每列乘以矩阵 [[1,4],[4,1]]，运算在 GF(2^4) 上进行。
        /// 状态按列排列：第 1 列为 s00、s10（即第 1、2 个半字节），第 2 列为 s01、s11（第 3、4 个半字节）。
        /// </summary>
        public static ushort MixColumns(ushort state)
        {
            byte s00 = GetNibble(state, 0);
            byte s10 = GetNibble(state, 1);
            byte s01 = GetNibble(state, 2);
            byte s11 = GetNibble(state, 3);

            byte r00 = Gf16.Add(s00, Gf16.Multiply(4, s10));
            byte r10 = Gf16.Add(Gf16.Multiply(4, s00), s10);
            byte r01 = Gf16.Add(s01, Gf16.Multiply(4, s11));
            byte r11 = Gf16.Add(Gf16.Multiply(4, s01), s11);

            return CombineState(r00, r10, r01, r11);
        }

        /// <summary>
        /// 逆列混淆：每列乘以矩阵 [[9,2],[2,9]]，运算在 GF(2^4) 上进行。
        /// </summary>
        public static ushort InvMixColumns(ushort state)
        {
            byte s00 = GetNibble(state, 0);
            byte s10 = GetNibble(state, 1);
            byte s01 = GetNibble(state, 2);
            byte s11 = GetNibble(state, 3);

            byte r00 = Gf16.Add(Gf16.Multiply(9, s00), Gf16.Multiply(2, s10));
            byte r10 = Gf16.Add(Gf16.Multiply(2, s00), Gf16.Multiply(9, s10));
            byte r01 = Gf16.Add(Gf16.Multiply(9, s01), Gf16.Multiply(2, s11));
            byte r11 = Gf16.Add(Gf16.Multiply(2, s01), Gf16.Multiply(9, s11));

            return CombineState(r00, r10, r01, r11);
        }

        // ---------- 状态矩阵辅助方法 ----------

        /// <summary>
        /// 按列优先的位序取半字节：index 0/1/2/3 依次对应 s00、s10、s01、s11
        /// （即 16 位状态的第 1、2、3、4 个半字节）。
        /// </summary>
        private static byte GetNibble(ushort state, int index)
            => (byte)((state >> (12 - 4 * index)) & 0x0F);

        private static ushort CombineState(byte s00, byte s10, byte s01, byte s11)
            => (ushort)((s00 << 12) | (s10 << 8) | (s01 << 4) | s11);

        private static void ValidateRoundKeys(ushort[] roundKeys)
        {
            if (roundKeys == null || roundKeys.Length < 3)
            {
                throw new System.ArgumentException("需要 3 个轮密钥（K0、K1、K2）。", nameof(roundKeys));
            }
        }
    }
}
