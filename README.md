# Gran Turismo 5 Save Editor

This command-line tool allows to read and edit saves of PlayStation 3 game Gran Turismo 5.

It can decrypt and rencrypt PS3 GT5 saves natively in C#, implementing all logics originally developed in, now classic, [flatz's pfdtool](https://github.com/bucanero/pfd_sfo_tools).

This tool can read various properties such as cash, days, A-spec wins, A-spec level/points, B-spec wins, B-spec level/points, and can edit cash, days, A-spec wins, A-spec level/points, B-spec wins, B-spec level/points, and other properties.

The code is a refactoring and bug fixing of the codes from the following sources:
- https://github.com/sean-halpin/gt5GarageEditor
- https://github.com/Tonic-Box/PS3-Save-Decrypter
- https://github.com/Wulf2k/DeS-SaveEdit/tree/master/DeS-SaveEdit
- https://github.com/Jappi88/Dark-Souls-II-SE

The sources ParamPFD.cs and PS3Crypto.cs are standalone classes that allow (theoretically) to encrypt/rencrypt all files protected by a PFD file for any game, provided its secure file id.

Some documentation about PFD files and how to decrypt and encrypt their protected files can be found in the following sources:
- https://www.psdevwiki.com/ps3/PARAM.PFD
- https://github.com/BuXXe/PARAM.PFD-PS3-Demons-Souls-Savegame-Tool/tree/master/documentation

A list of secure file ids for various games can be found in the following source:
- https://github.com/Nicba1010/PS-Tools/blob/master/format/pfd/games.conf
