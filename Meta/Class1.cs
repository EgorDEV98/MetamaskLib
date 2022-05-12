using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Meta
{
    public class Metamask : MetamaskData
    {
        MetamaskData m_data;
        public Metamask(string json)
        {
            this.json = json;
            DeserilizeJSON();
        }

        private void DeserilizeJSON()
        {
            if(string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException("JSON");
            }
            m_data = JsonConvert.DeserializeObject<MetamaskData>(this.json);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="passwordBytes">byte[] Пароль</param>
        /// <param name="saltBytes">byte[] Соль</param>
        /// <returns>Возвращает ключ</returns>
        public byte[] DrivedKey(byte[] passwordBytes,byte[] saltBytes)
        {
            return PBKDF2.DeriveKey(passwordBytes, saltBytes, 10000, 256, HMAC.Create("HMACSHA256"));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">Данные (data)</param>
        /// <param name="key">Ключ дешифровки полученный из DerivedKey()</param>
        /// <param name="iv">Вектор</param>
        /// <returns>Возвращает дешифрованную JSON строку</returns>
        public string Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            try
            {
                GcmBlockCipher gcmBlockCipher = new GcmBlockCipher(new AesFastEngine());
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
                gcmBlockCipher.Init(false, parameters);
                byte[] plainBytes = new byte[gcmBlockCipher.GetOutputSize(data.Length)];
                int retLen = gcmBlockCipher.ProcessBytes(data, 0, data.Length, plainBytes, 0);
                gcmBlockCipher.DoFinal(plainBytes, retLen);
                return Encoding.UTF8.GetString(plainBytes).TrimEnd("\r\n\0".ToCharArray());
            }
            catch 
            {
                throw new Exception("Неверный пароль");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="passwords">Лист паролей</param>
        /// <param name="showResult">True - показывать результаты</param>
        /// <returns>Возвращает дешифрованную JSON строку</returns>
        public string BrutePassword(List<string> passwords, bool showResult = false)
        {
            foreach(var pwd in passwords)
            {
                try
                {
                    byte[] key = DrivedKey(
                        Encoding.UTF8.GetBytes(pwd),
                        m_data.GetByteSalt());
                    string result = Decrypt(m_data.GetByteData(), key, m_data.GetByteIV());
                    if (showResult) Console.WriteLine("Password: " + pwd, Console.ForegroundColor = ConsoleColor.Green);
                    return result;
                }
                catch
                {
                    if (showResult) Console.WriteLine("Incorrect password: " + pwd, Console.ForegroundColor = ConsoleColor.Red);
                }
            }
            return "";
        }

        /// <summary>
        /// Многопоточный подбор пароля
        /// </summary>
        /// <param name="passwords">Массив паролей</param>
        /// <param name="threadCount">Число потоков(рекомендуется не больше 20)</param>
        /// <returns>Возвращает дешифрованную JSON строку</returns>
        public string BrutePasswordMultithread(List<string> passwords, int threadCount)
        {
            return "";
        }

        /// <summary>
        /// Получить представление о данных
        /// </summary>
        /// <returns>MetamaskData</returns>
        public MetamaskData GetMetamaskData()
        {
            return m_data;
        }


        private readonly string json;
    }

    public class MetamaskData
    {
        protected string data { get; set; }
        protected string iv { get; set; }
        protected string salt { get; set; }

        public byte[] GetByteData()
        {
            return StringToByte(this.data);
        }
        public byte[] GetByteIV()
        {
            return StringToByte(this.iv);
        }
        public byte[] GetByteSalt()
        {
            return StringToByte(this.salt);
        }
        private byte[] StringToByte(string data)
        {
            return Convert.FromBase64String(data);
        }
    }
}
