using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Text;
using System.Windows.Forms;
using SAesCore;

namespace SAesGui
{
    /// <summary>
    /// 图形界面：包含基本加解密、字符串扩展、双重/三重加密、中间相遇攻击、CBC 工作模式与自检页面。
    /// </summary>
    public sealed class MainForm : Form
    {
        private readonly Font uiFont = new Font("Microsoft YaHei UI", 9.5F);
        private readonly Font monoFont = new Font("Consolas", 10.5F);
        private readonly Font resultFont = new Font("Consolas", 16F, FontStyle.Bold);

        private TabControl tabMain;

        // 第 1 关：基本加解密
        private TextBox txtBasicPlain;
        private TextBox txtBasicKey;
        private TextBox txtBasicResult;
        private TextBox txtBasicTrace;

        // 第 3 关：字符串
        private TextBox txtTextPlain;
        private TextBox txtTextKey;
        private TextBox txtTextHex;
        private TextBox txtTextAscii;
        private TextBox txtTextRestored;

        // 第 4.1 关：双重加密
        private TextBox txtDoubleKey;
        private TextBox txtDoubleInput;
        private TextBox txtDoubleResult;

        // 第 4.2 关：中间相遇攻击
        private TextBox txtPairs;
        private TextBox txtMitmResult;

        // 第 4.3 关：三重加密
        private RadioButton rbTripleTwoKeys;
        private RadioButton rbTripleThreeKeys;
        private TextBox txtTripleKey;
        private TextBox txtTripleInput;
        private TextBox txtTripleResult;

        // 第 5 关：CBC
        private TextBox txtCbcKey;
        private TextBox txtCbcIv;
        private TextBox txtCbcPlain;
        private TextBox txtCbcCipher;
        private TextBox txtCbcBaseOut;
        private TextBox txtCbcCurOut;
        private TextBox txtCbcDiff;
        private TextBox txtTamperIndex;
        private ushort[] baselineCipherBlocks;

        // 自检
        private TextBox txtSelfTestReport;

        public MainForm()
        {
            Text = "S-AES 算法实现 —— 信息安全导论 作业2";
            Font = uiFont;
            ClientSize = new Size(1000, 650);
            MinimumSize = new Size(1000, 690);
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            Load += (sender, args) => FillDefaultMitmPairs();
        }

        // ==================== 界面构建 ====================

        private void BuildUi()
        {
            tabMain = new TabControl { Dock = DockStyle.Fill };
            Controls.Add(tabMain);

            BuildBasicTab();
            BuildStringTab();
            BuildDoubleTab();
            BuildMeetInTheMiddleTab();
            BuildTripleTab();
            BuildCbcTab();
            BuildSelfTestTab();
        }

        private void BuildBasicTab()
        {
            TabPage page = CreateTab("1. 基本加解密");

            CreateLabel(page, "明文（16 位，4 位十六进制，例如 6F6B）", 20, 18);
            txtBasicPlain = CreateTextBox(page, "6F6B", 20, 44, 260, 0, font: new Font("Consolas", 14F));

            CreateLabel(page, "密钥（16 位，4 位十六进制，例如 2D55）", 320, 18);
            txtBasicKey = CreateTextBox(page, "2D55", 320, 44, 260, 0, font: new Font("Consolas", 14F));

            CreateButton(page, "加密", 20, 92, 110, BasicEncryptClicked);
            CreateButton(page, "解密", 150, 92, 110, BasicDecryptClicked);

            CreateLabel(page, "结果（16 位密文 / 明文）", 20, 140);
            txtBasicResult = CreateTextBox(page, string.Empty, 20, 166, 420, 0, readOnly: true, font: resultFont);

            CreateLabel(page, "加解密过程（每个轮函数的中间状态）", 20, 222);
            txtBasicTrace = CreateTextBox(page, string.Empty, 20, 248, 960, 330, multiline: true, readOnly: true, font: monoFont);

            CreateNote(page, "说明：分组与密钥均为 16 位；加密流程为 AK0 →（NS、SR、MC、AK1）→（NS、SR、AK2），解密为严格逆序。", 20, 590, 960);
        }

        private void BuildStringTab()
        {
            TabPage page = CreateTab("2. 字符串扩展");

            CreateLabel(page, "明文文本（按 2 字节一组处理，奇数长度末尾补 0x00）", 20, 18);
            txtTextPlain = CreateTextBox(page, "信息安全导论 S-AES", 20, 44, 640, 110, multiline: true, font: monoFont);

            CreateLabel(page, "密钥（4 位十六进制）", 680, 18);
            txtTextKey = CreateTextBox(page, "2D55", 680, 44, 200, 0, font: new Font("Consolas", 14F));

            CreateButton(page, "加密", 20, 172, 120, TextEncryptClicked);
            CreateButton(page, "解密（按下方密文）", 160, 172, 180, TextDecryptClicked);

            CreateLabel(page, "密文（十六进制，每 4 位一组，可编辑后用于解密）", 20, 220);
            txtTextHex = CreateTextBox(page, string.Empty, 20, 246, 960, 80, multiline: true, font: monoFont);

            CreateLabel(page, "密文的字符形式（不可打印字符以 \\xNN 表示，通常为乱码）", 20, 340);
            txtTextAscii = CreateTextBox(page, string.Empty, 20, 366, 960, 60, multiline: true, readOnly: true, font: monoFont);

            CreateLabel(page, "解密还原的文本", 20, 440);
            txtTextRestored = CreateTextBox(page, string.Empty, 20, 466, 960, 100, multiline: true, readOnly: true, font: monoFont);

            CreateNote(page, "说明：采用 UTF-8 编码后按 2 字节分组（ASCII 字符串的编码与 ASCII 一致），因此密文以 16 位分组的形式呈现。", 20, 580, 960);
        }

        private void BuildDoubleTab()
        {
            TabPage page = CreateTab("3. 双重加密");

            CreateLabel(page, "32 位密钥（K1 + K2，8 位十六进制）", 20, 18);
            txtDoubleKey = CreateTextBox(page, "2D5555AA", 20, 44, 320, 0, font: new Font("Consolas", 14F));

            CreateLabel(page, "明文 / 密文（16 位）", 380, 18);
            txtDoubleInput = CreateTextBox(page, "6F6B", 380, 44, 240, 0, font: new Font("Consolas", 14F));

            CreateButton(page, "加密", 20, 98, 120, DoubleEncryptClicked);
            CreateButton(page, "解密", 160, 98, 120, DoubleDecryptClicked);

            CreateLabel(page, "结果（16 位）", 20, 150);
            txtDoubleResult = CreateTextBox(page, string.Empty, 20, 176, 420, 0, readOnly: true, font: resultFont);

            CreateNote(page, "定义：双重加密 C = E_K2(E_K1(P))，双重解密 P = D_K1(D_K2(C))；分组长度仍为 16 位，密钥长度扩展为 32 位。", 20, 240, 960);
        }

        private void BuildMeetInTheMiddleTab()
        {
            TabPage page = CreateTab("4. 中间相遇攻击");

            CreateLabel(page, "已知明密文对（每行一组：明文HEX, 密文HEX；至少 1 组，2 组以上可保证唯一）", 20, 18);
            txtPairs = CreateTextBox(page, string.Empty, 20, 44, 500, 170, multiline: true, font: monoFont);

            CreateButton(page, "执行中间相遇攻击", 20, 230, 190, MitmAttackClicked);

            CreateLabel(page, "攻击结果", 20, 280);
            txtMitmResult = CreateTextBox(page, string.Empty, 20, 306, 960, 290, multiline: true, readOnly: true, font: monoFont);

            CreateNote(page, "原理：用第一组明密文建立 2^16 个 E_K1(P0) 的中间值索引，再遍历 K2 计算 D_K2(C0) 并查表命中，最后用其余明密文对验证。", 20, 610, 960);
        }

        private void BuildTripleTab()
        {
            TabPage page = CreateTab("5. 三重加密");

            rbTripleTwoKeys = new RadioButton
            {
                Text = "32 位密钥模式（K1+K2，三次加密：K1、K2、K1）",
                Location = new Point(20, 18),
                AutoSize = true,
                Checked = true,
                Font = uiFont
            };
            page.Controls.Add(rbTripleTwoKeys);

            rbTripleThreeKeys = new RadioButton
            {
                Text = "48 位密钥模式（K1+K2+K3）",
                Location = new Point(420, 18),
                AutoSize = true,
                Font = uiFont
            };
            page.Controls.Add(rbTripleThreeKeys);

            rbTripleTwoKeys.CheckedChanged += TripleModeChanged;
            rbTripleThreeKeys.CheckedChanged += TripleModeChanged;

            CreateLabel(page, "密钥（16 位或 24 位十六进制）", 20, 58);
            txtTripleKey = CreateTextBox(page, "2D5555AA", 20, 84, 340, 0, font: new Font("Consolas", 14F));

            CreateLabel(page, "明文 / 密文（16 位）", 400, 58);
            txtTripleInput = CreateTextBox(page, "6F6B", 400, 84, 240, 0, font: new Font("Consolas", 14F));

            CreateButton(page, "加密", 20, 138, 120, TripleEncryptClicked);
            CreateButton(page, "解密", 160, 138, 120, TripleDecryptClicked);

            CreateLabel(page, "结果（16 位）", 20, 190);
            txtTripleResult = CreateTextBox(page, string.Empty, 20, 216, 420, 0, readOnly: true, font: resultFont);

            CreateNote(page, "定义：32 位密钥模式 C = E_K1(E_K2(E_K1(P)))；48 位密钥模式 C = E_K3(E_K2(E_K1(P)))。解密按加密的逆序进行。", 20, 280, 960);
        }

        private void BuildCbcTab()
        {
            TabPage page = CreateTab("6. CBC 工作模式");

            CreateLabel(page, "密钥（4 位十六进制）", 20, 18);
            txtCbcKey = CreateTextBox(page, "2D55", 20, 44, 150, 0, font: new Font("Consolas", 14F));

            CreateLabel(page, "初始向量 IV（4 位十六进制，双方共享）", 200, 18);
            txtCbcIv = CreateTextBox(page, "A5A5", 200, 44, 150, 0, font: new Font("Consolas", 14F));

            CreateLabel(page, "明文（可多分组）", 20, 84);
            txtCbcPlain = CreateTextBox(page, "CBC 模式演示：信息安全导论 S-AES，分组链接工作模式。", 20, 110, 960, 60, multiline: true, font: monoFont);

            CreateButton(page, "加密", 20, 182, 110, CbcEncryptClicked);
            CreateButton(page, "解密并对比", 150, 182, 140, CbcCompareClicked);

            CreateLabel(page, "密文（每 4 位十六进制一块，可手工编辑以模拟篡改）", 20, 224);
            txtCbcCipher = CreateTextBox(page, string.Empty, 20, 250, 960, 55, multiline: true, font: monoFont);

            CreateLabel(page, "篡改第", 20, 316);
            txtTamperIndex = CreateTextBox(page, "1", 82, 312, 50, 0, font: new Font("Consolas", 12F));
            CreateLabel(page, "块的首字节", 142, 316);
            CreateButton(page, "篡改该块", 260, 312, 110, CbcTamperClicked);
            CreateButton(page, "恢复原始密文", 382, 312, 130, CbcRestoreClicked);

            CreateLabel(page, "基准解密结果（原始密文）", 20, 358);
            txtCbcBaseOut = CreateTextBox(page, string.Empty, 20, 384, 460, 55, multiline: true, readOnly: true, font: monoFont);

            CreateLabel(page, "当前解密结果（篡改后的密文）", 520, 358);
            txtCbcCurOut = CreateTextBox(page, string.Empty, 520, 384, 460, 55, multiline: true, readOnly: true, font: monoFont);

            CreateLabel(page, "逐块差异分析", 20, 448);
            txtCbcDiff = CreateTextBox(page, string.Empty, 20, 474, 960, 95, multiline: true, readOnly: true, font: monoFont);

            CreateNote(page, "CBC 特性：修改第 i 个密文分组会使第 i 块明文随机改变，并使第 i+1 块出现相同比特位置的翻转，后续分组不受影响。", 20, 585, 960);
        }

        private void BuildSelfTestTab()
        {
            TabPage page = CreateTab("7. 程序自检");

            CreateButton(page, "运行全部自检（5 个关卡）", 20, 18, 240, SelfTestClicked);

            txtSelfTestReport = CreateTextBox(page, string.Empty, 20, 60, 960, 540, multiline: true, readOnly: true, font: monoFont);
            txtSelfTestReport.Text = "点击上方按钮运行自检，结果将显示在这里。";
        }

        // ==================== 控件辅助方法 ====================

        private TabPage CreateTab(string title)
        {
            TabPage page = new TabPage(title) { Font = uiFont, Padding = new Padding(0) };
            tabMain.TabPages.Add(page);
            return page;
        }

        private Label CreateLabel(Control parent, string text, int x, int y)
        {
            Label label = new Label
            {
                Text = text,
                Location = new Point(x, y),
                AutoSize = true,
                Font = uiFont
            };
            parent.Controls.Add(label);
            return label;
        }

        private void CreateNote(Control parent, string text, int x, int y, int width)
        {
            Label note = new Label
            {
                Text = text,
                Location = new Point(x, y),
                AutoSize = true,
                MaximumSize = new Size(width, 0),
                ForeColor = Color.DimGray,
                Font = uiFont
            };
            parent.Controls.Add(note);
        }

        private TextBox CreateTextBox(Control parent, string text, int x, int y, int width, int height,
            bool multiline = false, bool readOnly = false, Font font = null)
        {
            TextBox box = new TextBox
            {
                Text = text,
                Location = new Point(x, y),
                Width = width,
                Multiline = multiline,
                ReadOnly = readOnly,
                Font = font ?? uiFont,
                ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None,
                WordWrap = multiline
            };

            if (multiline)
            {
                box.Height = height;
            }
            else
            {
                box.Width = width;
            }

            parent.Controls.Add(box);
            return box;
        }

        private void CreateButton(Control parent, string text, int x, int y, int width, EventHandler clickHandler)
        {
            Button button = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(width, 30),
                Font = uiFont
            };
            button.Click += clickHandler;
            parent.Controls.Add(button);
        }

        // ==================== 输入解析 ====================

        private static string NormalizeHex(string text)
        {
            string cleaned = (text ?? string.Empty).Trim().Replace(" ", string.Empty);
            if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(2);
            }

            return cleaned;
        }

        private bool TryReadHex16(string text, out ushort value, string fieldName)
        {
            string cleaned = NormalizeHex(text);
            if (cleaned.Length != 4 ||
                !ushort.TryParse(cleaned, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
            {
                Warn(fieldName + " 必须是 4 位十六进制数（例如 6F6B）。");
                value = 0;
                return false;
            }

            return true;
        }

        private bool TryReadKey32(string text, out ushort key1, out ushort key2, string fieldName)
        {
            key1 = 0;
            key2 = 0;
            string cleaned = NormalizeHex(text);

            if (cleaned.Length != 8 ||
                !ushort.TryParse(cleaned.Substring(0, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out key1) ||
                !ushort.TryParse(cleaned.Substring(4, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out key2))
            {
                Warn(fieldName + " 必须是 8 位十六进制数（K1 与 K2 各 4 位）。");
                return false;
            }

            return true;
        }

        private bool TryReadKey48(string text, out ushort key1, out ushort key2, out ushort key3, string fieldName)
        {
            key1 = 0;
            key2 = 0;
            key3 = 0;
            string cleaned = NormalizeHex(text);

            if (cleaned.Length != 12 ||
                !ushort.TryParse(cleaned.Substring(0, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out key1) ||
                !ushort.TryParse(cleaned.Substring(4, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out key2) ||
                !ushort.TryParse(cleaned.Substring(8, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out key3))
            {
                Warn(fieldName + " 必须是 12 位十六进制数（K1、K2、K3 各 4 位）。");
                return false;
            }

            return true;
        }

        private static void Warn(string message)
        {
            MessageBox.Show(message, "输入有误", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        // ==================== 第 1、2 关：基本加解密 ====================

        private void BasicEncryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtBasicPlain.Text, out ushort plaintext, "明文") ||
                !TryReadHex16(txtBasicKey.Text, out ushort key, "密钥"))
            {
                return;
            }

            ushort ciphertext = SAes.Encrypt(plaintext, key);
            txtBasicResult.Text = ciphertext.ToString("X4");
            ShowTrace(SAes.EncryptTrace(plaintext, key), key, "加密");
        }

        private void BasicDecryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtBasicPlain.Text, out ushort ciphertext, "密文") ||
                !TryReadHex16(txtBasicKey.Text, out ushort key, "密钥"))
            {
                return;
            }

            ushort plaintext = SAes.Decrypt(ciphertext, key);
            txtBasicResult.Text = plaintext.ToString("X4");
            ShowTrace(SAes.DecryptTrace(ciphertext, key), key, "解密");
        }

        private void ShowTrace(List<StepTrace> trace, ushort key, string title)
        {
            StringBuilder builder = new StringBuilder();
            ushort[] roundKeys = KeyExpansion.Expand(key);

            builder.AppendLine(title + "  ——  轮密钥：K0=" + roundKeys[0].ToString("X4") +
                               "  K1=" + roundKeys[1].ToString("X4") +
                               "  K2=" + roundKeys[2].ToString("X4"));
            builder.AppendLine(new string('-', 56));

            int index = 1;
            foreach (StepTrace step in trace)
            {
                builder.AppendLine(index.ToString("D2") + ". " + step.Name.PadRight(24, ' ') + step.StateHex);
                index++;
            }

            txtBasicTrace.Text = builder.ToString();
        }

        // ==================== 第 3 关：字符串 ====================

        private void TextEncryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtTextKey.Text, out ushort key, "密钥"))
            {
                return;
            }

            byte[] bytes = BlockStringCipher.ToBytes(txtTextPlain.Text);
            ushort[] blocks = BlockStringCipher.EncryptBytes(bytes, key);

            txtTextHex.Text = BlockStringCipher.ToHex(blocks);
            txtTextAscii.Text = BlockStringCipher.EscapeBlocks(blocks);
            txtTextRestored.Text = "(加密完成，可点击“解密”验证还原结果)";
        }

        private void TextDecryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtTextKey.Text, out ushort key, "密钥"))
            {
                return;
            }

            ushort[] blocks;
            try
            {
                blocks = BlockStringCipher.ParseHexBlocks(txtTextHex.Text);
            }
            catch (FormatException error)
            {
                Warn(error.Message);
                return;
            }

            byte[] bytes = BlockStringCipher.DecryptBlocks(blocks, key);
            txtTextRestored.Text = Encoding.UTF8.GetString(bytes).TrimEnd('\0');
            txtTextAscii.Text = BlockStringCipher.EscapeBlocks(blocks);
        }

        // ==================== 第 4.1 关：双重加密 ====================

        private void DoubleEncryptClicked(object sender, EventArgs args)
        {
            if (!TryReadKey32(txtDoubleKey.Text, out ushort key1, out ushort key2, "密钥") ||
                !TryReadHex16(txtDoubleInput.Text, out ushort plaintext, "明文"))
            {
                return;
            }

            txtDoubleResult.Text = MultipleEncryption.DoubleEncrypt(plaintext, key1, key2).ToString("X4");
        }

        private void DoubleDecryptClicked(object sender, EventArgs args)
        {
            if (!TryReadKey32(txtDoubleKey.Text, out ushort key1, out ushort key2, "密钥") ||
                !TryReadHex16(txtDoubleInput.Text, out ushort ciphertext, "密文"))
            {
                return;
            }

            txtDoubleResult.Text = MultipleEncryption.DoubleDecrypt(ciphertext, key1, key2).ToString("X4");
        }

        // ==================== 第 4.2 关：中间相遇攻击 ====================

        private void FillDefaultMitmPairs()
        {
            // 默认样例：K1=2D55，K2=55AA，明文 6F6B / 1234 / A5C3 对应的密文对
            StringBuilder builder = new StringBuilder();
            foreach (ushort plaintext in new ushort[] { 0x6F6B, 0x1234, 0xA5C3 })
            {
                ushort ciphertext = MultipleEncryption.DoubleEncrypt(plaintext, 0x2D55, 0x55AA);
                builder.AppendLine(plaintext.ToString("X4") + ", " + ciphertext.ToString("X4"));
            }

            txtPairs.Text = builder.ToString().TrimEnd();
        }

        private void MitmAttackClicked(object sender, EventArgs args)
        {
            List<KnownPair> pairs = new List<KnownPair>();

            foreach (string rawLine in txtPairs.Lines)
            {
                string line = rawLine.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                string[] parts = line.Split(new[] { ',', '，', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2 ||
                    parts[0].Length != 4 || parts[1].Length != 4 ||
                    !ushort.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort plaintext) ||
                    !ushort.TryParse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort ciphertext))
                {
                    Warn("明密文对格式错误：应为每行“明文HEX, 密文HEX”（各 4 位十六进制）。");
                    return;
                }

                pairs.Add(new KnownPair(plaintext, ciphertext));
            }

            if (pairs.Count == 0)
            {
                Warn("请至少输入一组已知明密文对。");
                return;
            }

            Cursor previous = Cursor;
            Cursor = Cursors.WaitCursor;
            try
            {
                MeetInTheMiddleResult result = MeetInTheMiddle.Attack(pairs);
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("使用已知明密文对：" + pairs.Count + " 组");
                builder.AppendLine("搜索空间：K1、K2 各 2^16 = 65536 种，共约 2^32 种组合");

                if (!result.Success)
                {
                    builder.AppendLine("未找到匹配的密钥组合，请检查明密文对是否由双重加密产生。");
                }
                else
                {
                    builder.AppendLine(string.Format("恢复出的密钥：K1 = {0:X4}，K2 = {1:X4}", result.Key1, result.Key2));
                    builder.AppendLine(string.Format("能通过全部明密文验证的密钥组合数量：{0} 个", result.ValidKeyPairCount));
                    builder.AppendLine(string.Format("实际耗时：{0} ms（约 2 × 2^16 次分组运算）", result.ElapsedMilliseconds));
                    builder.AppendLine();
                    builder.AppendLine("验证：对每组已知明文重新双重加密，结果均与给定密文一致。");
                }

                txtMitmResult.Text = builder.ToString();
            }
            finally
            {
                Cursor = previous;
            }
        }

        // ==================== 第 4.3 关：三重加密 ====================

        private void TripleModeChanged(object sender, EventArgs args)
        {
            if (rbTripleThreeKeys.Checked)
            {
                if (NormalizeHex(txtTripleKey.Text).Length <= 8)
                {
                    txtTripleKey.Text = "2D5555AA1234";
                }
            }
            else if (rbTripleTwoKeys.Checked)
            {
                if (NormalizeHex(txtTripleKey.Text).Length > 8)
                {
                    txtTripleKey.Text = "2D5555AA";
                }
            }
        }

        private void TripleEncryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtTripleInput.Text, out ushort plaintext, "明文"))
            {
                return;
            }

            if (rbTripleThreeKeys.Checked)
            {
                if (!TryReadKey48(txtTripleKey.Text, out ushort key1, out ushort key2, out ushort key3, "密钥"))
                {
                    return;
                }

                txtTripleResult.Text = MultipleEncryption.TripleEncrypt(plaintext, key1, key2, key3).ToString("X4");
            }
            else
            {
                if (!TryReadKey32(txtTripleKey.Text, out ushort key1, out ushort key2, "密钥"))
                {
                    return;
                }

                txtTripleResult.Text = MultipleEncryption.TripleEncrypt(plaintext, key1, key2).ToString("X4");
            }
        }

        private void TripleDecryptClicked(object sender, EventArgs args)
        {
            if (!TryReadHex16(txtTripleInput.Text, out ushort ciphertext, "密文"))
            {
                return;
            }

            if (rbTripleThreeKeys.Checked)
            {
                if (!TryReadKey48(txtTripleKey.Text, out ushort key1, out ushort key2, out ushort key3, "密钥"))
                {
                    return;
                }

                txtTripleResult.Text = MultipleEncryption.TripleDecrypt(ciphertext, key1, key2, key3).ToString("X4");
            }
            else
            {
                if (!TryReadKey32(txtTripleKey.Text, out ushort key1, out ushort key2, "密钥"))
                {
                    return;
                }

                txtTripleResult.Text = MultipleEncryption.TripleDecrypt(ciphertext, key1, key2).ToString("X4");
            }
        }

        // ==================== 第 5 关：CBC ====================

        private bool TryReadCbcParameters(out ushort key, out ushort iv)
        {
            key = 0;
            iv = 0;
            return TryReadHex16(txtCbcKey.Text, out key, "密钥") && TryReadHex16(txtCbcIv.Text, out iv, "IV");
        }

        private void CbcEncryptClicked(object sender, EventArgs args)
        {
            if (!TryReadCbcParameters(out ushort key, out ushort iv))
            {
                return;
            }

            byte[] plainBytes = BlockStringCipher.ToBytes(txtCbcPlain.Text);
            ushort[] blocks = CbcMode.Encrypt(plainBytes, key, iv);
            baselineCipherBlocks = blocks;

            txtCbcCipher.Text = BlockStringCipher.ToHex(blocks);
            ShowCbcComparison(blocks, blocks, key, iv, "尚未篡改，当前密文与原始密文相同。");
        }

        private void CbcCompareClicked(object sender, EventArgs args)
        {
            if (!TryReadCbcParameters(out ushort key, out ushort iv))
            {
                return;
            }

            ushort[] currentBlocks;
            try
            {
                currentBlocks = BlockStringCipher.ParseHexBlocks(txtCbcCipher.Text);
            }
            catch (FormatException error)
            {
                Warn(error.Message);
                return;
            }

            if (baselineCipherBlocks == null)
            {
                byte[] plainBytes = CbcMode.Decrypt(currentBlocks, key, iv);
                txtCbcBaseOut.Text = "(尚无基准密文，请先点击“加密”)";
                txtCbcCurOut.Text = Encoding.UTF8.GetString(plainBytes).TrimEnd('\0');
                txtCbcDiff.Text = "尚无基准密文可供对比。";
                return;
            }

            if (baselineCipherBlocks.Length != currentBlocks.Length)
            {
                Warn("当前密文的分组数量与原始密文不同，无法逐块对比。");
                return;
            }

            ShowCbcComparison(baselineCipherBlocks, currentBlocks, key, iv,
                tamperHint: "当前密文与原始密文相同，未发生篡改。");
        }

        private void ShowCbcComparison(ushort[] baseline, ushort[] current, ushort key, ushort iv, string tamperHint)
        {
            byte[] baselinePlain = CbcMode.Decrypt(baseline, key, iv);
            byte[] currentPlain = CbcMode.Decrypt(current, key, iv);

            txtCbcBaseOut.Text = Encoding.UTF8.GetString(baselinePlain).TrimEnd('\0');
            txtCbcCurOut.Text = Encoding.UTF8.GetString(currentPlain).TrimEnd('\0');

            bool same = true;
            for (int i = 0; i < baseline.Length && same; i++)
            {
                same = baseline[i] == current[i];
            }

            string difference = CbcMode.DescribeBlockDifferences(baselinePlain, currentPlain);
            txtCbcDiff.Text = (same ? tamperHint + Environment.NewLine : "检测到密文被篡改：" + Environment.NewLine) + difference;
        }

        private void CbcTamperClicked(object sender, EventArgs args)
        {
            ushort[] blocks;
            try
            {
                blocks = BlockStringCipher.ParseHexBlocks(txtCbcCipher.Text);
            }
            catch (FormatException error)
            {
                Warn(error.Message);
                return;
            }

            if (!int.TryParse(txtTamperIndex.Text.Trim(), out int blockNumber) ||
                blockNumber < 1 || blockNumber > blocks.Length)
            {
                Warn("请输入有效的分组序号（从 1 开始，且不超过密文分组数量 " + blocks.Length + "）。");
                return;
            }

            blocks[blockNumber - 1] ^= 0x0100; // 翻转该分组最高字节的最低位
            txtCbcCipher.Text = BlockStringCipher.ToHex(blocks);
            CbcCompareClicked(sender, args);
        }

        private void CbcRestoreClicked(object sender, EventArgs args)
        {
            if (baselineCipherBlocks == null)
            {
                Warn("尚无原始密文，请先点击“加密”。");
                return;
            }

            txtCbcCipher.Text = BlockStringCipher.ToHex(baselineCipherBlocks);
            CbcCompareClicked(sender, args);
        }

        // ==================== 自检 ====================

        private void SelfTestClicked(object sender, EventArgs args)
        {
            Cursor previous = Cursor;
            Cursor = Cursors.WaitCursor;
            try
            {
                txtSelfTestReport.Text = SelfTest.Run();
            }
            finally
            {
                Cursor = previous;
            }
        }
    }
}
