using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using TokenValidation.Constant;

namespace TokenValidation.Utilities
{
    /// <summary>
    /// It encrypts the plain text to cipher text and decrypts the cipher text to plain text.
    /// </summary>
    public class CryptoUtil
    {
        /// <summary>
        /// It encrypts the normal string to cipher text
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string EncryptString(string plainText)
        {
            try
            {
                byte[] encrypted;

                // Create a RijndaelManaged object with the specified key and IV.  
                using (var rijAlg = new RijndaelManaged())
                {
                    rijAlg.Mode = CipherMode.CBC;
                    rijAlg.Padding = PaddingMode.PKCS7;
                    rijAlg.FeedbackSize = 128;

                    rijAlg.Key = Encoding.UTF8.GetBytes(CloudConstant.Key);
                    rijAlg.IV = Encoding.UTF8.GetBytes(CloudConstant.IV);

                    // Create a decrytor to perform the stream transform.  
                    var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                    // Create the streams used for encryption.  
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.  
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                return System.Net.WebUtility.UrlEncode(Convert.ToBase64String(encrypted).Replace(CloudConstant.SlashChar, CloudConstant.SafeChar, StringComparison.InvariantCulture));
            }
            catch
            {
                return "Input parametrs are not valid.";
            }
        }

        /// <summary>
        /// It decrypts the cipher text to normal text
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string DecryptString(string cipherText)
        {
            try
            {
                // Check arguments.  
                if (cipherText == null || cipherText.Length <= 0)
                {
                    throw new ArgumentNullException("cipherText");
                }
                cipherText= HttpUtility.UrlDecode(cipherText);

                var encrypted = Convert.FromBase64String(cipherText.Replace(CloudConstant.SafeChar, CloudConstant.SlashChar, StringComparison.InvariantCulture));
                // Declare the string used to hold the decrypted text.  
                string plainText = string.Empty;

                // Create an RijndaelManaged object with the specified key and IV.  
                using (var rijAlg = new RijndaelManaged())
                {
                    //Settings  
                    rijAlg.Mode = CipherMode.CBC;
                    rijAlg.Padding = PaddingMode.PKCS7;
                    rijAlg.FeedbackSize = 128;

                    rijAlg.Key = Encoding.UTF8.GetBytes(CloudConstant.Key);
                    rijAlg.IV = Encoding.UTF8.GetBytes(CloudConstant.IV);

                    // Create a decrytor to perform the stream transform.  
                    var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);


                    // Create the streams used for decryption.  
                    using (var msDecrypt = new MemoryStream(encrypted))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream  
                                // and place them in a string.  
                                plainText = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plainText;
            }
            catch
            {
                return "Input parametrs are not valid.";
            }
        }
    }
}
