using System;

public class GT5SaveEditor {

    private static class Args {
        public static bool decrypt;
        public static bool encrypt;
        public static bool read;
        public static string root;
        public static List<string> props;
        public static List<string> vals;
    }

    private static void ParseArgs(string[] args) {
        if(args.Length == 0) return;
        var indices = new List<int>();
        int i = Array.FindIndex(args, arg => string.Equals(arg, "-dec", StringComparison.OrdinalIgnoreCase));
        Args.decrypt = i > 0;
        indices.Add(i);
        i = Array.FindIndex(args, arg => string.Equals(arg, "-enc", StringComparison.OrdinalIgnoreCase));
        Args.encrypt = i > 0;
        indices.Add(i);
        i = Array.FindIndex(args, arg => string.Equals(arg, "-read", StringComparison.OrdinalIgnoreCase));
        Args.read = i > 0;
        indices.Add(i);
        int j = Array.FindIndex(args, arg => string.Equals(arg, "-root", StringComparison.OrdinalIgnoreCase));
        if(j < 0 || j == args.Length - 1) return;
        indices.Add(j);
        Args.root = args[j + 1];
        indices.Add(j + 1);
        Args.props = new List<string>();
        Args.vals = new List<string>();
        if(Args.decrypt || Args.encrypt || Args.read) return;
        for(int k = 0; k < args.Length - 1; k += 2) {
            if(indices.IndexOf(k) > 0 || indices.IndexOf(k + 1) > 0) continue;
            Args.props.Add(args[k].Replace("-", ""));
            Args.vals.Add(args[k + 1]);
        }
    }

    public static void Main(string[] args) {
        ParseArgs(args);
        ParamPFD pfd = new ParamPFD(Args.root, GT5Save.securefileid);
        if(Args.decrypt) {
            pfd.DecryptAllFiles();
        }
        else if(Args.encrypt) {
            pfd.RebuilParamPFD();
        }
        else if(Args.read) {
            pfd.DecryptAllFiles();
            var path = Path.Combine(Args.root, "GT5.0");
            var save = new GT5Save(path);
            save.PrintInfos();
            pfd.RebuilParamPFD();
        }
        else {
            pfd.DecryptAllFiles();
            var path = Path.Combine(Args.root, "GT5.0");
            var save = new GT5Save(path);
            for(int i = 0; i < Args.props.Count; i++) save.UpdateItem(Args.props[i], Args.vals[i]);
            pfd.RebuilParamPFD();
        }
    }
}