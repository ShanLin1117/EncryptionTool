using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace EncryptionTool.WPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string? currentFilePath;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnEncryptText_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(txtInput.Text))
                {
                    ShowError("請輸入要加密的文字！");
                    return;
                }

                if (txtKey.SecurePassword.Length < 16)
                {
                    ShowError("金鑰長度必須至少16個字元！");
                    return;
                }

                string key = new System.Net.NetworkCredential(string.Empty, txtKey.SecurePassword).Password;
                string encryptedText = EncryptString(txtInput.Text, key);
                txtOutput.Text = encryptedText;
                ShowStatus("文字加密完成");
            }
            catch (Exception ex)
            {
                ShowError($"加密過程發生錯誤: {ex.Message}");
            }
        }

        private void btnDecryptText_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(txtInput.Text))
                {
                    ShowError("請輸入要解密的文字！");
                    return;
                }

                if (txtKey.SecurePassword.Length < 16)
                {
                    ShowError("金鑰長度必須至少16個字元！");
                    return;
                }

                string key = new System.Net.NetworkCredential(string.Empty, txtKey.SecurePassword).Password;
                string decryptedText = DecryptString(txtInput.Text, key);
                txtOutput.Text = decryptedText;
                ShowStatus("文字解密完成");
            }
            catch (Exception ex)
            {
                ShowError($"解密過程發生錯誤: {ex.Message}");
            }
        }

        private void btnEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "選擇要加密的檔案"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    if (txtKey.SecurePassword.Length < 16)
                    {
                        ShowError("金鑰長度必須至少16個字元！");
                        return;
                    }

                    string key = new System.Net.NetworkCredential(string.Empty, txtKey.SecurePassword).Password;
                    string encryptedFilePath = openFileDialog.FileName + ".encrypted";

                    EncryptFile(openFileDialog.FileName, encryptedFilePath, key);
                    currentFilePath = openFileDialog.FileName;
                    txtSelectedFile.Text = Path.GetFileName(currentFilePath);
                    ShowStatus($"檔案加密完成: {encryptedFilePath}");
                }
                catch (Exception ex)
                {
                    ShowError($"檔案加密過程發生錯誤: {ex.Message}");
                }
            }
        }

        private void btnDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "選擇要解密的檔案",
                Filter = "加密檔案 (*.encrypted)|*.encrypted|所有檔案 (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    if (txtKey.SecurePassword.Length < 16)
                    {
                        ShowError("金鑰長度必須至少16個字元！");
                        return;
                    }

                    string key = new System.Net.NetworkCredential(string.Empty, txtKey.SecurePassword).Password;
                    string decryptedFilePath = openFileDialog.FileName.Replace(".encrypted", ".decrypted");

                    DecryptFile(openFileDialog.FileName, decryptedFilePath, key);
                    currentFilePath = openFileDialog.FileName;
                    txtSelectedFile.Text = Path.GetFileName(currentFilePath);
                    ShowStatus($"檔案解密完成: {decryptedFilePath}");
                }
                catch (Exception ex)
                {
                    ShowError($"檔案解密過程發生錯誤: {ex.Message}");
                }
            }
        }

        private void ShowError(string message)
        {
            MessageBox.Show(message, "錯誤", MessageBoxButton.OK, MessageBoxImage.Error);
            ShowStatus(message);
        }

        private void ShowStatus(string message)
        {
            statusMessage.Content = message;
        }

        private static string EncryptString(string plainText, string key)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }

                    array = memoryStream.ToArray();
                }
            }

            return Convert.ToBase64String(array);
        }

        private static string DecryptString(string cipherText, string key)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (StreamReader streamReader = new StreamReader(cryptoStream))
                {
                    return streamReader.ReadToEnd();
                }
            }
        }

        private static void EncryptFile(string inputFile, string outputFile, string key)
        {
            byte[] iv = new byte[16];
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                using (FileStream fsCrypt = new FileStream(outputFile, FileMode.Create))
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
                    {
                        fsIn.CopyTo(cs);
                    }
                }
            }
        }

        private static void DecryptFile(string inputFile, string outputFile, string key)
        {
            byte[] iv = new byte[16];
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
                aes.IV = iv;

                using (FileStream fsCrypt = new FileStream(inputFile, FileMode.Open))
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
                    {
                        cs.CopyTo(fsOut);
                    }
                }
            }
        }
    }
}