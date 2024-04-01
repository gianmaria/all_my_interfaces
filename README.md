# nic

A tool for windows that allows you to change the Network Interface Card's metric on your computer.

```
C:\> nic help

Usage: nic [<empty> | dump | load | help]

nic
   print info on installed nic

nic dump file.json
   produce a json file that allows you to reorder the nic priority

nic load file.json (requires elevation)
   reorder the nic priority based on the order in the json file

nic help
   show this help
```
