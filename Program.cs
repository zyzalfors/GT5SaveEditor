using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using PS3SaveDecrypt;

public class GT5SaveEditor {

    private enum State {start, path, prop}

    private class Argv {
        public bool encrypt;
        public bool decrypt;
        public bool read;
        public string root;
        public List<string> props;
        public List<string> vals;
    }

    private static Argv Parse(string[] args) {
        var state = State.start;

        var argv = new Argv {
            encrypt = false,
            decrypt = false,
            read = false,
            root = null,
            props = new List<string>(),
            vals = new List<string>()
        };

        foreach(var arg in args) {
            if(string.Equals(arg, "enc", StringComparison.OrdinalIgnoreCase)) {
                argv.encrypt = true;
                state = State.start;
            }
            else if(string.Equals(arg, "dec", StringComparison.OrdinalIgnoreCase)) {
                argv.decrypt = true;
                state = State.start;
            }
            else if(string.Equals(arg, "read", StringComparison.OrdinalIgnoreCase)) {
                argv.read = true;
                state = State.start;
            }
            else if(string.Equals(arg, "root", StringComparison.OrdinalIgnoreCase)) {
                state = State.path;
            }
            else if(state == State.path && argv.root == null) {
                argv.root = arg;
                state = State.start;
            }
            else if(Regex.IsMatch(arg, "[a-z]+", RegexOptions.IgnoreCase)) {
                argv.props.Add(arg);
                state = State.prop;
            }
            else if(state == State.prop) {
                argv.vals.Add(arg);
                state = State.start;
            }
        }

        return argv;
    }

    public static void Main(string[] args) {
        var argv = Parse(args);
        var pfd = new ParamPFD(argv.root, GT5Save.securefileid);

        if(argv.decrypt) {
            pfd.DecryptAllFiles();
        }
        else if(argv.encrypt) {
            pfd.Rebuild();
        }
        else if(argv.read) {
            pfd.DecryptAllFiles();
            var path = Path.Combine(argv.root, "GT5.0");
            var save = new GT5Save(path);
            save.PrintInfos();
            pfd.Rebuild();
        }
        else {
            pfd.DecryptAllFiles();
            var path = Path.Combine(argv.root, "GT5.0");
            var save = new GT5Save(path);

            for(int i = 0; i < argv.props.Count; i++)
                save.UpdateItem(argv.props[i], argv.vals[i]);

            pfd.Rebuild();
        }
    }
}