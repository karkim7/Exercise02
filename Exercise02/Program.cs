using System;
using System.IO;
using System.Text;
using System.Xml.Linq;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        // Original values
        string name = "Bob Smith";
        string creditCard = "1234-5678-9012-3456";
        string password = "Pa$$w0rd";

        // Secret key (must be 16 characters for AES-128)
        string secretKey = "thisisasecretkey!";

        // Encrypt credit card
        string encryptedCreditCard = Encrypt(creditCard, secretKey);

        // Hash password with salt
        string salt = GenerateSalt();
        string hashedPassword = HashPassword(password, salt);

        // Save to protected XML
        XElement customer = new XElement("customer",
            new XElement("name", name),
            new XElement("creditcard", encryptedCreditCard),
            new XElement("password", hashedPassword),
            new XElement("salt", salt)
        );

        XElement root = new XElement("customers", customer);
        root.Save("customers_protected.xml");

        Console.WriteLine("Encrypted & hashed data saved to customers_protected.xml");

        // --------------------------
        // Decrypt the credit card
        // --------------------------
        string decryptedCard = Decrypt(encryptedCreditCard, secretKey);
        Console.WriteLine("Decrypted Credit Card: " + decryptedCard);
    }

    // Encrypt using AES
    static string Encrypt(string plainText, string key)
    {
        byte[] iv = new byte[16];
        byte[] encrypted;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key.PadRight(16).Substring(0, 16));
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new())
            using (CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write))
            using (StreamWriter sw = new(cs))
            {
                sw.Write(plainText);
                sw.Close();
                encrypted = ms.ToArray();
            }
        }

        return Convert.ToBase64String(encrypted);
    }

    // Decrypt AES encrypted data
    static string Decrypt(string encryptedText, string key)
    {
        byte[] iv = new byte[16];
        byte[] buffer = Convert.FromBase64String(encryptedText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key.PadRight(16).Substring(0, 16));
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using MemoryStream ms = new(buffer);
            using CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Read);
            using StreamReader reader = new(cs);
            return reader.ReadToEnd();
        }
    }

    // Hash password with salt using SHA256
    static string HashPassword(string password, string salt)
    {
        using SHA256 sha256 = SHA256.Create();
        byte[] inputBytes = Encoding.UTF8.GetBytes(password + salt);
        byte[] hashBytes = sha256.ComputeHash(inputBytes);
        return Convert.ToBase64String(hashBytes);
    }

    // Generate a random salt string
    static string GenerateSalt()
    {
        byte[] saltBytes = new byte[16];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(saltBytes);
        return Convert.ToBase64String(saltBytes);
    }
}
