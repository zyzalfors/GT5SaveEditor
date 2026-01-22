using System;
using System.Security.Cryptography;

namespace PS3SaveDecrypt {

    internal static class PS3Crypto {

        internal static readonly byte[] syscon_manager_key = new byte[] {0xD4, 0x13, 0xB8, 0x96, 0x63, 0xE1, 0xFE, 0x9F, 0x75, 0x14, 0x3D, 0x3B, 0xB4, 0x56, 0x52, 0x74};
        internal static readonly byte[] keygen_key = new byte[] {0x6B, 0x1A, 0xCE, 0xA2, 0x46, 0xB7, 0x45, 0xFD, 0x8F, 0x93, 0x76, 0x3B, 0x92, 0x05, 0x94, 0xCD, 0x53, 0x48, 0x3B, 0x82};

        internal static ulong SwapByteOrder(ulong value) {
            return ((value & 0xff00000000000000L) >> 56) |
                   ((value & 0x00ff000000000000L) >> 40) |
                   ((value & 0x0000ff0000000000L) >> 24) |
                   ((value & 0x000000ff00000000L) >> 8) |
                   ((value & 0x00000000ff000000L) << 8) |
                   ((value & 0x0000000000ff0000L) << 24) |
                   ((value & 0x000000000000ff00L) << 40) |
                   ((value & 0x00000000000000ffL) << 56);
        }

        internal static byte[] DecryptWithPortability(byte[] iv, byte[] data) {
            Array.Resize(ref iv, 16);

            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            return aes.CreateDecryptor(syscon_manager_key, iv).TransformFinalBlock(data, 0, data.Length);
        }

        internal static byte[] EncryptWithPortability(byte[] iv, byte[] data) {
            Array.Resize(ref iv, 16);

            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            return aes.CreateEncryptor(syscon_manager_key, iv).TransformFinalBlock(data, 0, data.Length);
        }

        internal static byte[] GetHMACSHA1(byte[] key, byte[] data) {
            return new HMACSHA1(key).ComputeHash(data, 0, data.Length);
        }

        internal static byte[] GetHMACSHA1(string path, byte[] key) {
            return new HMACSHA1(key).ComputeHash(File.Open(path, FileMode.Open, FileAccess.Read));
        }

        public static byte[] Decrypt(byte[] key, byte[] data) {
            Array.Resize(ref key, 16);

            var aes1 = Aes.Create();
            aes1.Key = key;
            aes1.BlockSize = 128;
            aes1.Mode = CipherMode.ECB;
            aes1.Padding = PaddingMode.Zeros;

            var aes2 = Aes.Create();
            aes2.Key = key;
            aes2.BlockSize = 128;
            aes2.Mode = CipherMode.ECB;
            aes2.Padding = PaddingMode.Zeros;

            var blocks = data.Length / 16;
            var output = new byte[data.Length];

            for(int i = 0; i < blocks; i++) {
                var blockData = new byte[16];
                Array.Copy(data, i * 16, blockData, 0, 16);

                var counterKey = new byte[16];
                Array.Copy(BitConverter.GetBytes(SwapByteOrder((ulong) i)), 0, counterKey, 0, 8);
                counterKey = aes1.CreateEncryptor().TransformFinalBlock(counterKey, 0, counterKey.Length);
                blockData = aes2.CreateDecryptor().TransformFinalBlock(blockData, 0, blockData.Length);

                for(int j = 0; j < 16; j++)
                    blockData[j] ^= counterKey[j];

                Array.Copy(blockData, 0, output, i * 16, 16);
            }

            return output;
        }

        public static byte[] Encrypt(byte[] key, byte[] data) {
            Array.Resize(ref key, 16);

            var aes1 = Aes.Create();
            aes1.Key = key;
            aes1.BlockSize = 128;
            aes1.Mode = CipherMode.ECB;
            aes1.Padding = PaddingMode.Zeros;

            var aes2 = Aes.Create();
            aes2.Key = key;
            aes2.BlockSize = 128;
            aes2.Mode = CipherMode.ECB;
            aes2.Padding = PaddingMode.Zeros;

            var blocks = data.Length / 16;
            var output = new byte[data.Length];

            for(int i = 0; i < blocks; i++) {
                var blockData = new byte[16];
                Array.Copy(data, i * 16, blockData, 0, 16);

                var counterKey = new byte[16];
                Array.Copy(BitConverter.GetBytes(SwapByteOrder((ulong) i)), 0, counterKey, 0, 8);
                counterKey = aes1.CreateEncryptor().TransformFinalBlock(counterKey, 0, counterKey.Length);

                for(int j = 0; j < 16; j++)
                    blockData[j] ^= counterKey[j];

                blockData = aes2.CreateEncryptor().TransformFinalBlock(blockData, 0, blockData.Length);
                Array.Copy(blockData, 0, output, i * 16, 16);
            }

            return output;
        }
    }
}