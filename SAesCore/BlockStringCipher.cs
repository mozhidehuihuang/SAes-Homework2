using System;
using System.Linq;
using System.Text;

namespace SAesCore
{
    /// <summary>
    /// 第 3 关扩展功能：按 2 字节（16 位）分组对字节串（如 ASCII 字符串）加解密。
    /// 明文长度若为奇数，末尾补一个 0x00 字节凑成整分组。
    /// 密文以 16 位分组的形式输出，可直接以十六进制或字符（可能是乱码）展示。
    /// </summary>
    public static class BlockStringCipher
    {
        /// <summary>将字节串按 2 字节分组加密，返回 16 位密文分组。</summary>
        public static ushort[] EncryptBytes(byte[] data, ushort key)
        {
            byte[] padded = PadToEvenLength(data);
            ushort[] blocks = new ushort[padded.Length / 2];

            for (int i = 0; i < blocks.Length; i++)
            {
                ushort block = (ushort)((padded[2 * i] << 8) | padded[2 * i + 1]);
                blocks[i] = SAes.Encrypt(block, key);
            }

            return blocks;
        }

        /// <summary>将 16 位密文分组逐块解密，返回字节串（可能包含补齐用的 0x00）。</summary>
        public static byte[] DecryptBlocks(ushort[] blocks, ushort key)
        {
            if (blocks == null)
            {
                throw new ArgumentNullException(nameof(blocks));
            }

            byte[] bytes = new byte[blocks.Length * 2];
            for (int i = 0; i < blocks.Length; i++)
            {
                ushort plain = SAes.Decrypt(blocks[i], key);
                bytes[2 * i] = (byte)(plain >> 8);
                bytes[2 * i + 1] = (byte)(plain & 0x00FF);
            }

            return bytes;
        }

        /// <summary>奇数长度时在末尾补 0x00。</summary>
        public static byte[] PadToEvenLength(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (data.Length % 2 == 0)
            {
                return data;
            }

            byte[] padded = new byte[data.Length + 1];
            Array.Copy(data, padded, data.Length);
            return padded;
        }

        /// <summary>格式化为以空格分隔的 4 位十六进制分组，例如 "3A7C 9F10"。</summary>
        public static string ToHex(ushort[] blocks)
            => string.Join(" ", blocks.Select(block => block.ToString("X4")));

        /// <summary>解析十六进制分组文本（允许空格、换行分隔，每 4 个十六进制字符为一组）。</summary>
        public static ushort[] ParseHexBlocks(string text)
        {
            if (text == null)
            {
                throw new ArgumentNullException(nameof(text));
            }

            string compact = new string(text.Where(ch => !char.IsWhiteSpace(ch)).ToArray());
            if (compact.Length == 0 || compact.Length % 4 != 0)
            {
                throw new FormatException("密文必须是 4 位十六进制的分组（每 2 字节一组）。");
            }

            ushort[] blocks = new ushort[compact.Length / 4];
            for (int i = 0; i < blocks.Length; i++)
            {
                if (!ushort.TryParse(compact.Substring(i * 4, 4), System.Globalization.NumberStyles.HexNumber, null, out ushort value))
                {
                    throw new FormatException("密文中包含非十六进制字符。");
                }

                blocks[i] = value;
            }

            return blocks;
        }

        /// <summary>把 16 位分组还原为字节串（高位字节在前）。</summary>
        public static byte[] BlocksToBytes(ushort[] blocks)
        {
            if (blocks == null)
            {
                throw new ArgumentNullException(nameof(blocks));
            }

            byte[] bytes = new byte[blocks.Length * 2];
            for (int i = 0; i < blocks.Length; i++)
            {
                bytes[2 * i] = (byte)(blocks[i] >> 8);
                bytes[2 * i + 1] = (byte)(blocks[i] & 0x00FF);
            }

            return bytes;
        }

        /// <summary>把单个字节转换为可读文本：可打印 ASCII 原样输出，其余用 \xNN 表示。</summary>
        public static string EscapeByte(byte value)
            => value >= 0x20 && value <= 0x7E ? ((char)value).ToString() : "\\x" + value.ToString("X2");

        /// <summary>把字节串转换为可读文本：可打印 ASCII 原样输出，其余用 \xNN 表示。</summary>
        public static string EscapeBytes(byte[] data, bool stopAtFirstZero = true)
        {
            if (data == null)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(data.Length);
            foreach (byte value in data)
            {
                if (stopAtFirstZero && value == 0)
                {
                    break;
                }

                builder.Append(EscapeByte(value));
            }

            return builder.ToString();
        }

        /// <summary>以“每个分组两个转义字节、分组间用空格分隔”的形式展示密文，避免可打印字符与转义序列混淆。</summary>
        public static string EscapeBlocks(ushort[] blocks)
        {
            if (blocks == null)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(blocks.Length * 10);
            for (int i = 0; i < blocks.Length; i++)
            {
                if (i > 0)
                {
                    builder.Append(' ');
                }

                builder.Append(EscapeByte((byte)(blocks[i] >> 8)));
                builder.Append(EscapeByte((byte)(blocks[i] & 0x00FF)));
            }

            return builder.ToString();
        }

        /// <summary>按 UTF-8 编码字符串（ASCII 字符编码结果与 ASCII 一致）。</summary>
        public static byte[] ToBytes(string text) => Encoding.UTF8.GetBytes(text ?? string.Empty);
    }
}
