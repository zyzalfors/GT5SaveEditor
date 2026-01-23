using PS3SaveDecrypt;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

public class GT5SaveEditor {
    public static void Main(string[] args) {
        if(args.Length < 2)
            return;

        var root = args[0];

        var pfd = new ParamPFD(root, GT5Save.securefileid);
        pfd.DecryptAllFiles();

        var path = Path.Combine(root, "GT5.0");
        var save = new GT5Save(path);

        for(int i = 1; i < args.Length; i++) {
            if(string.Equals(args[i], "read", StringComparison.OrdinalIgnoreCase))
                save.PrintInfos();
            else if(string.Equals(args[i], "goldlic", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.GoldLicenses);
            else if(string.Equals(args[i], "goldaspec", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.GoldAspec);
            else if(string.Equals(args[i], "goldbspec", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.GoldBspec);
            else if(string.Equals(args[i], "goldspec", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.GoldSpecial);
            else if(string.Equals(args[i], "allgifts", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.AllGifts);
            else if(string.Equals(args[i], "maxmoney", StringComparison.OrdinalIgnoreCase))
                save.Process(GT5Save.Commands.MaxMoney);
            else if(Regex.IsMatch(args[i], "^[^\\s=]+=[^\\s=]+$", RegexOptions.IgnoreCase)) {
                var parts = args[i].Split("=");
                save.UpdateItem(parts[0], parts[1]);
            }
        }

        pfd.Rebuild();
    }
}