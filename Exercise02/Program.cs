using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.IO;

class Program
{
    static void Main()
    {
        string filePath = "customers.xml";

        // Sample XML file
        string xmlContent = @"<?xml version=""1.0"" encoding=""utf-8""?>
<customers>
  <customer>
    <name>Bob Smith</name>
    <creditcard>1234-5678-9012-3456</creditcard>
    <password>Pa$$w0rd</password>
  </customer>
</customers>";
        File.WriteAllText(filePath, xmlContent);

        XDocument doc = XDocument.Load(filePath);
        string key = "thisisasecretkey!"; // 16 characters = 128-bit key

        foreach (var customer in doc.Descendants("customer"))
        {
            string creditCard = customer.Element("creditcard").Value;
            string password = customer.Element("password").Value;

            // Encrypt credit card
            string encryptedCard = Encrypt(creditCard, key);
            customer.Element("creditcard").Value = encryptedCard;

            // Salt and hash password
            string hashedPassword = HashPasswordWithSalt(password);
            customer.Element("password").Value = hashedPassword;
        }

        doc.Save("customers_protected.xml");
        Console.WriteLine("Protected data saved to customers_protected.xml");
    }

    // AES Encryption (Symmetric)
    static string Encrypt(string plainText, string key)
    {
        byte[] iv = new byte[16];
        byte[] encrypted;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key.PadRight(16).Substring(0, 16));
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write);
            using (StreamWriter sw = new(cs))
            {
                sw.Write(plainText);
            }

            encrypted = ms.ToArray();
        }

        return Convert.ToBase64String(encrypted);
    }

    // SHA256 + Salt
    static string HashPasswordWithSalt(string password)
    {
        byte[] salt = new byte[16];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltedPassword = new byte[salt.Length + passwordBytes.Length];
        Buffer.BlockCopy(salt, 0, saltedPassword, 0, salt.Length);
        Buffer.BlockCopy(passwordBytes, 0, saltedPassword, salt.Length, passwordBytes.Length);

        using SHA256 sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(saltedPassword);

        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }
}
