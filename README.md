# Gran Turismo 5 Save Editor

This command-line tool allows users to read and edit save files for the PlayStation 3 game Gran Turismo 5.

It can decrypt and re-encrypt PS3 GT5 saves natively in C#, implementing all the logic originally developed in the now-classic [flatz's pfdtool](https://github.com/bucanero/pfd_sfo_tools).

The tool can read various properties such as cash, days, A-spec wins, A-spec level/points, B-spec wins, B-spec level/points, and more. It also allows editing of properties like cash, days, A-spec wins, A-spec level/points, B-spec wins, B-spec level/points, and other game-related data.

The code is a refactored and bug-fixed version of code from the following sources:
- https://github.com/sean-halpin/gt5GarageEditor
- https://github.com/Tonic-Box/PS3-Save-Decrypter
- https://github.com/Wulf2k/DeS-SaveEdit/tree/master/DeS-SaveEdit
- https://github.com/Jappi88/Dark-Souls-II-SE

The ParamPFD.cs and PS3Crypto.cs files are standalone codes that theoretically allow encryption and re-encryption of all files protected by a PFD file for any game, provided its secure file ID.

Documentation about PFD files and how to decrypt and encrypt their protected files can be found here:
- https://www.psdevwiki.com/ps3/PARAM.PFD
- https://github.com/BuXXe/PARAM.PFD-PS3-Demons-Souls-Savegame-Tool/tree/master/documentation

A list of secure file IDs for various games is available here:
- https://github.com/Nicba1010/PS-Tools/blob/master/format/pfd/games.conf
