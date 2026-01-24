using Microsoft.Data.Sqlite;
using SQLitePCL;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

public class GT5Save {
    private readonly string _path;
    private readonly List<int> _itemOffsets;
    private readonly List<int> _list0;
    private List<int> _list1;
    private uint _tableLength;
    private long _keysOffset;
    private readonly List<string> _itemsKeys;
    private const int _headerMagic = 249;
    private const long _headerLength = 32;
    private const string _sqLiteFileMagic = "SQLite format 3";
    private const long _firstItemOffset = 42;
    private const long _startOffsetReadStart = 33;
    private ulong _dbOffset;
    private string _dbPath;
    public const string securefileid = "BDBD2EB72D82473DBE09F1B552A93FE6";
    public enum Command {GoldLicenses, GoldAspec, GoldBspec, GoldSpecial, AllGifts, MaxMoney}

    public GT5Save(string path) {
        _path = path;
        _itemOffsets = new List<int>();
        _list0 = new List<int>();
        _itemsKeys = new List<string>();
        ReadInfos();
        InitDb();
    }

    private static ulong ReverseEndianess(uint begin, uint end, byte[] buff) {
        uint num = 0;

        for(uint i = begin; i <= end; i++)
            num = i != begin ? num << 8 | buff[i] : buff[i];

        return num;
    }

    private void InitDb() {
        byte[] dbBuffer;

        using(var fs = new FileStream(_path, FileMode.Open) {Position = (long) _dbOffset}) {
            using(var ms = new MemoryStream()) {
                fs.CopyTo(ms);
                dbBuffer = ms.ToArray();
            }
        }

        _dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "temp.db");
        File.WriteAllBytes(_dbPath, dbBuffer);
        Batteries.Init();
    }

    private void ReadInfos() {
        var headerMagic = 0;

        using(var fs = new FileStream(_path, FileMode.Open) {Position = 3}) {
            headerMagic = (byte) fs.ReadByte();
        }

        if(headerMagic == _headerMagic) {
            ReadItemInfos();
            _dbOffset = GetSqlLiteOffset();
        }
    }

    public void PrintInfos() {
        var itemsKey = new List<string>(_itemsKeys);
        itemsKey.Sort();

        foreach(var key in itemsKey) {
            var infos = GetItemInfos(key);
            var offset = (long) infos[0];
            var value = (ulong) infos[1];
            Console.WriteLine(key + " at " + offset.ToString() + ": " + value.ToString());
        }

        Console.WriteLine("SQLite at " + _dbOffset.ToString());
    }

    private void ReadItemInfos() {
        using(var fs = new FileStream(_path, FileMode.Open) {Position = _startOffsetReadStart}) {
            var buff = new byte[4];
            fs.Read(buff, 0, 4);

            _tableLength = (uint) ReverseEndianess(0, 3, buff);
            fs.Position = _firstItemOffset;
            _keysOffset = _tableLength + _headerLength;

            bool flag = false;
            var dataTypeExtended = new byte[5];
            byte value = 0;

            while(fs.Position < _keysOffset)
                ReadValues(fs, dataTypeExtended, ref value, ref flag);

            _list1 = _list0.Distinct().ToList();
            _list1.Sort();
            fs.Position += 2;

            foreach(int i in _list1)
                _itemsKeys.Add(ReadItemKey(fs));
        }
    }

    private object[] GetItemInfos(string key) {
        long offset = 0;
        ulong val = 0;

        using(var fs = new FileStream(_path, FileMode.Open) {Position = GetItemOffset(key)}) {
            if(((byte) fs.ReadByte()) == 7) {
                var buff = new byte[8];
                var temp = (byte) fs.ReadByte();

                if(temp <= sbyte.MaxValue)
                    fs.Position++;
                else if(temp <= 129)
                    fs.Position += 2;

                offset = fs.Position;
                int length = 0;

                while(((byte) fs.ReadByte()) != 7)
                    length++;

                fs.Position = offset;

                switch(length) {
                    case 1:
                        fs.Read(buff, 7, 1);
                        val = ReverseEndianess(7, 7, buff);
                        break;

                    case 2:
                        fs.Read(buff, 6, 2);
                        val = ReverseEndianess(6, 7, buff);
                        break;

                    case 4:
                        fs.Read(buff, 4, 4);
                        val = ReverseEndianess(4, 7, buff);
                        break;

                    case 8:
                        fs.Read(buff, 0, 8);
                        val = ReverseEndianess(0, 7, buff);
                        break;
                }
            }
        }

        return new object[2] {offset, val};
    }

    public void UpdateItem(string key, string val) {
        using(var fs = new FileStream(_path, FileMode.Open) {Position = GetItemOffset(key)}) {
            ulong value = ulong.Parse(val);
            var buff = new byte[8];

            if(((byte) fs.ReadByte()) == 7) {
                var temp = (byte) fs.ReadByte();

                if(temp <= sbyte.MaxValue)
                    fs.Position++;
                else if(temp <= 129)
                    fs.Position += 2;

                long offset = fs.Position;
                int length = 0;

                while(((byte) fs.ReadByte()) != 7)
                    length++;

                fs.Position = offset;

                switch(length) {
                    case 1:
                        ConvertToSaveValue(buff, 7, 1, value);
                        fs.Write(buff, 7, 1);
                        break;

                    case 2:
                        ConvertToSaveValue(buff, 6, 2, value);
                        fs.Write(buff, 6, 2);
                        break;

                    case 4:
                        ConvertToSaveValue(buff, 4, 4, value);
                        fs.Write(buff, 4, 4);
                        break;

                    case 8:
                        ConvertToSaveValue(buff, 0, 8, value);
                        fs.Write(buff, 0, 8);
                        break;
                }
            }
        }
    }

    private static void ConvertToSaveValue(byte[] buff, uint start, uint length, ulong value) {
        switch(length) {
            case 1:
                buff[start] = (byte) (value & byte.MaxValue);
                break;

            case 2:
                buff[start] = (byte) (value >> 8 & byte.MaxValue);
                buff[start + 1] = (byte) (value & byte.MaxValue);
                break;

            case 4:
                buff[start] = (byte) (value >> 24 & byte.MaxValue);
                buff[start + 1] = (byte) (value >> 16 & byte.MaxValue);
                buff[start + 2] = (byte) (value >> 8 & byte.MaxValue);
                buff[start + 3] = (byte) (value & byte.MaxValue);
                break;

            case 8:
                buff[start] = (byte) (value >> 56 & byte.MaxValue);
                buff[start + 1] = (byte) (value >> 48 & byte.MaxValue);
                buff[start + 2] = (byte) (value >> 40 & byte.MaxValue);
                buff[start + 3] = (byte) (value >> 32 & byte.MaxValue);
                buff[start + 4] = (byte) (value >> 24 & byte.MaxValue);
                buff[start + 5] = (byte) (value >> 16 & byte.MaxValue);
                buff[start + 6] = (byte) (value >> 8 & byte.MaxValue);
                buff[start + 7] = (byte) (value & byte.MaxValue);
                break;

        }
    }

    private int GetItemOffset(string key) {
        try {
            int indexOfItemName = _itemsKeys.IndexOf(key);
            int index = _list0.IndexOf(_list1[indexOfItemName]);
            return _itemOffsets[index];
        }
        catch {
            return 0;
        }
    }

    private ulong GetSqlLiteOffset() {
        ulong off = 0;

        using(var fs = new FileStream(_path, FileMode.Open)) {
            bool flag = false;
            var magicBytes = Encoding.ASCII.GetBytes(_sqLiteFileMagic);
            var buff = new byte[_sqLiteFileMagic.Length];

            while(!flag && fs.Position < fs.Length) {
                if(((char) fs.ReadByte()) == magicBytes[0]) {
                    fs.Position--;
                    fs.Read(buff, 0, _sqLiteFileMagic.Length);

                    if(AreByteArraysEquivalent(magicBytes, buff)) {
                        flag = true;
                        off = ((ulong) fs.Position) - ((ulong) _sqLiteFileMagic.Length);
                    }
                }
            }
        }

        return off;
    }

    private static string ReadItemKey(FileStream fs) {
        try {
            var key = new StringBuilder(string.Empty);
            var keySize = fs.ReadByte();

            for(int i = 0; i < keySize; i++)
                key.Append((char) fs.ReadByte());

            return key.ToString();
        }
        catch {
            return string.Empty;
        }
    }

    private void ReadValues(FileStream fs, byte[] dataTypeExtended, ref byte value, ref bool flag) {
        var dataType = (byte) fs.ReadByte();
        dataTypeExtended[0] = dataType;
        if(dataType != 7)
            return;

        dataType = (byte) fs.ReadByte();
        dataTypeExtended[1] = dataType;

        if(dataType <= sbyte.MaxValue)
            ReadValue(fs, dataTypeExtended, ref value, ref flag);
        else {
            if(dataType > 129)
                return;

            dataType = (byte) fs.ReadByte();
            dataTypeExtended[2] = dataType;
            ReadValue(fs, dataTypeExtended, ref value, ref flag);
        }
    }

    private void ReadValue(FileStream fs, byte[] dataTypeExtended, ref byte value, ref bool flag) {
        var buff = new byte[4];
        int temp = 0;
        byte dataType = 0;

        value = (byte) fs.ReadByte();
        int itemOffset = dataTypeExtended[1] > sbyte.MaxValue ? ((int) fs.Position) - 4 : ((int) fs.Position) - 3;

        switch(value) {
            case 0:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                break;

            case 1:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position++;
                break;

            case 2:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 2;
                break;

            case 3:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 4;
                break;

            case 4:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 8;
                break;

            case 5:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 4;
                break;

            case 6:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Read(buff, 0, 4);
                temp = (int) ReverseEndianess(0, 3, buff);
                fs.Position += temp;
                break;

            case 7:
                flag = false;
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position--;
                break;

            case 8:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Read(buff, 0, 4);
                temp = (int) ReverseEndianess(0, 3, buff);
                dataType = (byte) fs.ReadByte();
                fs.Position--;

                if(dataType == 7) {
                    flag = false;

                    for(int i = 0; i < temp; i++)
                        ReadValues(fs, dataTypeExtended, ref value, ref flag);
                }
                else {
                    flag = true;

                    for(int i = 0; i < temp; i++)
                        ReadValue(fs, dataTypeExtended, ref value, ref flag);

                    flag = false;
                }
                break;

            case 9:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Read(buff, 0, 4);
                temp = (int) ReverseEndianess(0, 3, buff);
                dataType = (byte) fs.ReadByte();
                fs.Position--;

                if(dataType == 7) {
                    flag = false;

                    for(int i = 0; i < temp; i++)
                        ReadValues(fs, dataTypeExtended, ref value, ref flag);
                }
                else {
                    flag = true;

                    for(int i = 0; i < temp * 2; i++)
                        ReadValue(fs, dataTypeExtended, ref value, ref flag);

                    flag = false;
                }
                break;

            case 10:
                dataType = (byte) fs.ReadByte();

                if(dataType == 9) {
                    ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                    fs.Read(buff, 0, 4);
                    temp = (int) ReverseEndianess(0, 3, buff);

                    for(int i = 0; i < temp; i++)
                        ReadValues(fs, dataTypeExtended, ref value, ref flag);
                }
                else {
                    if(dataType != 6)
                        break;

                    ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                    fs.Position += 8;
                    fs.Read(buff, 0, 4);
                    temp = (int) ReverseEndianess(0, 3, buff);
                    fs.Position += temp * 16;
                }
                break;

            case 12:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 1;
                break;

            case 13:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 2;
                break;

            case 14:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 4;
                break;

            case 15:
                ReadItemOffset(dataTypeExtended, value, flag, itemOffset);
                fs.Position += 8;
                break;
        }
    }

    private void ReadItemOffset(byte[] dataTypeExtended, byte value, bool flag, int itemOffset) {
        if(flag || value >= 16)
            return;

        if(value == 7) {
            if(dataTypeExtended[1] == 128 || dataTypeExtended[1] == 129) {
                _list0.Add((int) ReverseEndianess(0, 2, dataTypeExtended));
                _itemOffsets.Add(itemOffset);
            }
            else {
                _itemOffsets.Add(itemOffset);
                _list0.Add((int) ReverseEndianess(0, 1, dataTypeExtended));
            }
        }
        else if(dataTypeExtended[1] <= sbyte.MaxValue) {
            _itemOffsets.Add(itemOffset);
            _list0.Add((int) ReverseEndianess(0, 1, dataTypeExtended));
        }
        else if(dataTypeExtended[1] <= 129) {
            _itemOffsets.Add(itemOffset);
            _list0.Add((int) ReverseEndianess(0, 2, dataTypeExtended));
        }
    }

    private static bool AreByteArraysEquivalent(byte[] array1, byte[] array2) {
        if(array1 == null || array2 == null)
            throw new ArgumentNullException();

        if(array1 == array2)
            return true;

        if(array1.Length != array2.Length)
            return false;

        for(int i = 0; i < array1.Length; i++) {
            if(array1[i] != array2[i])
                return false;
        }

        return true;
    }

    private void UpdateDb(string query) {
        using(var connection = new SqliteConnection($"Data Source={_dbPath};Pooling=False")) {
            connection.Open();

            using(var command = connection.CreateCommand()) {
                command.CommandText = query;
                command.ExecuteNonQuery();
            }
        }
    }

    public void Process(Command cmd) {
        var updateDb = true;

        switch(cmd) {
            case Command.GoldLicenses:
                UpdateDb("UPDATE t_license SET result = 0");
                break;

            case Command.GoldAspec:
                UpdateDb("UPDATE t_aspec_race SET result = 0");
                break;

            case Command.GoldBspec:
                UpdateDb("UPDATE t_bspec_race SET result = 0");
                break;

            case Command.GoldSpecial:
                UpdateDb("UPDATE t_special_event SET result = 0");
                break;

            case Command.AllGifts:
                UpdateDb("UPDATE t_event_present SET get_flag = 0");
                break;

            case Command.MaxMoney:
                UpdateItem("cash", "20000000");
                updateDb = false;
                break;
        }

        if(!updateDb)
            return;

        var dbBuffer = File.ReadAllBytes(_dbPath);
        using(var fs = new FileStream(_path, FileMode.Open) {Position = (long) _dbOffset}) {
            fs.Write(dbBuffer, 0, dbBuffer.Length);
        }
    }
}