using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Hysakrypt2
{
    public class HysaAes
    {
        public string LastError { get; private set; }

        /// <summary>
        /// Encrypt files using AES.
        /// </summary>
        /// <param name="filePath">The file to encrypt.</param>
        /// <param name="password">The key to use.</param>
        /// <returns>0: success. -1: generic error.</returns>
        public int Encrypt(string filePath, string password, int keySize = 128, int blockSize = 128)
        {
            // generate random salt
            var salt = GenerateRandomSalt();

            // create output file name
            var fsCrypt = new FileStream(filePath + ".hysae", FileMode.Create);

            // convert password string to byte arrray
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            // Set Rijndael symmetric encryption algorithm
            var AES = new RijndaelManaged();
            AES.KeySize = keySize;
            AES.BlockSize = blockSize;
            AES.Padding = PaddingMode.PKCS7;

            // http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            // "What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            // Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            var cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            var fsIn = new FileStream(filePath, FileMode.Open);

            // create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            var buffer = new byte[1048576];

            try
            {
                int read;
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }

                fsIn.Close();

            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return -1;
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();

                File.Delete(filePath);
                File.Move(filePath + ".hysae", filePath);
            }

            return 0;
        }

        /// <summary>
        /// Decrypt the AES encrypted file using it's encryption key.
        /// </summary>
        /// <param name="filePath">The file to decrypt.</param>
        /// <param name="password">The encryption key to use.</param>
        /// <returns>0: success. -1: generic error. -2: cryptographic error.</returns>
        public int Decrypt(string filePath, string password, int keySize = 128, int blockSize = 128)
        {
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var salt = new byte[32];

            var fsCrypt = new FileStream(filePath, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            var AES = new RijndaelManaged();
            AES.KeySize = keySize;
            AES.BlockSize = blockSize;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            var cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            var fsOut = new FileStream(filePath + ".hysad", FileMode.Create);

            var buffer = new byte[1048576];

            try
            {
                int read;
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex)
            {
                LastError = ex.Message;

                if (ex.Message.StartsWith("Padding is"))
                {
                    LastError = "Invalid decryption key.";
                }

                try
                {
                    File.Delete(filePath + ".hysad");
                }
                catch
                {
                    // ignored
                }

                return -2;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;

                try
                {
                    File.Delete(filePath + ".hysad");
                }
                catch
                {
                    // ignored
                }

                return -1;
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                LastError = ex.Message;

                try
                {
                    File.Delete(filePath + ".hysad");
                }
                catch
                {
                    // ignored
                }

                return -1;
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();

                File.Delete(filePath);
                File.Move(filePath + ".hysad", filePath);
            }

            return 0;
        }

        private static byte[] GenerateRandomSalt()
        {
            // Source: http://www.dotnetperls.com/rngcryptoserviceprovider
            var data = new byte[32];

            using var rng = new RNGCryptoServiceProvider();
            // Ten iterations.
            for (var i = 0; i < 10; i++)
            {
                // Fill buffer.
                rng.GetBytes(data);
            }

            return data;
        }

        public static string GenerateEncryptionKey(int intKeyLength)
        {
            var chrChars = new char[]
            {
                'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F', 'g', 'G', 'h', 'H', 'i', 'I', 'j',
                'J', 'k', 'K', 'l', 'L', 'm', 'M', 'n', 'N', 'o', 'O', 'p', 'P', 'q', 'Q', 'r', 'R', 's', 'S',
                't', 'T', 'u', 'U', 'v', 'V', 'w', 'W', 'x', 'X', 'y', 'Y', 'z', 'Z', '0', '1', '2', '3', '4',
                '5', '6', '7', '8', '9', '?', '!', ';', ':', '@', '#'
            };

            var intPos = 0;
            var sbKey = new StringBuilder();
            var rnd = new Random();

            while (intPos < intKeyLength)
            {
                var intRand = rnd.Next(0, chrChars.Length - 1);
                sbKey.Append(chrChars[intRand]);
                intPos++;
            }

            return sbKey.ToString();
        }
    }
}