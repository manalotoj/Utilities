//------------------------------------------------------------------------------
// <copyright file="CSSqlFunction.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
using System;
using System.IO;
using System.Security.Cryptography;

public partial class UserDefinedFunctions
{
    /// <summary>
    /// Encrypt data
    /// </summary>
    /// <param name="value">string value to encrypt</param>
    /// <param name="key">base64 key</param>
    /// <param name="iv">base64 initialization vector</param>
    /// <returns></returns>
    [Microsoft.SqlServer.Server.SqlFunction]
    public static string Encrypt(string value, string key, string iv)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        return CryptoHelper.Encrypt(value, key, iv);
    }

    /// <summary>
    /// Decrypt data
    /// </summary>
    /// <param name="value">string value to encrypt</param>
    /// <param name="key">base64 key</param>
    /// <param name="iv">base64 initialization vector</param>
    /// <returns></returns>
    [Microsoft.SqlServer.Server.SqlFunction]
    public static string Decrypt(string value, string key, string iv)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        return CryptoHelper.Decrypt(value, key, iv);
    }

    public static class CryptoHelper
    {
        /// <summary>
        /// Encrypt string value.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key">base64 key</param>
        /// <param name="iv">base64 iv</param>
        /// <returns></returns>
        public static string Encrypt(string plainText, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(plainText)) return plainText;

            var rijndaelManaged = new RijndaelManaged();
            ICryptoTransform encryptor = rijndaelManaged.CreateEncryptor(GetBytes(key), GetBytes(iv));
            byte[] encrypted = null;

            using (var encryptedMemoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(encryptedMemoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(cryptoStream))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = encryptedMemoryStream.ToArray();
                }
            }
            return GetString(encrypted);
        }

        /// <summary>
        /// Decrypt string value
        /// </summary>
        /// <param name="encryptedText">encrypted string</param>
        /// <param name="key">base64 key</param>
        /// <param name="iv">base64 iv</param>
        /// <returns></returns>
        public static string Decrypt(string encryptedText, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(encryptedText)) return encryptedText;

            var rijndaelManaged = new RijndaelManaged();
            ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(GetBytes(key), GetBytes(iv));
            string plainText;

            using (var msDecrypt = new MemoryStream(GetBytes(encryptedText)))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        plainText = srDecrypt.ReadToEnd();
                    }
                }
            }
            return plainText;
        }

        private static byte[] GetBytes(string str)
        {
            return Convert.FromBase64String(str);
        }

        private static string GetString(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }
}
