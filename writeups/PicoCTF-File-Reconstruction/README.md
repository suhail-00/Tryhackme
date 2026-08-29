# PicoCTF – File Reconstruction Challenge

**Category:** Forensics / Linux Fundamentals  
**Difficulty:** Easy  
**Platform:** PicoCTF  
**Flag:** `picoCTF{z1p_and_spl1t_f1l3s_4r3_fun_2d6c5d3f}`

---

## Overview

This challenge presented a set of split file fragments alongside a password-protected archive. The objective was to reconstruct the original file from its parts, identify the file type, extract the archive using the correct password, and retrieve the hidden flag.

---

## Reconnaissance

After connecting to the challenge environment, listing the directory revealed the following files:

```bash
$ ls -la
```

```
combined_files
instructions.txt
part_aa
part_ab
part_ac
part_ad
part_ae
```

Reading `instructions.txt` gave clear direction:

```bash
$ grep -r "zip" instructions.txt
```

```
instructions.txt:- The flag is split into multiple parts as a zipped file.
instructions.txt:- The zip file is password protected. Use this "supersecret" password to extract the zip file.
instructions.txt:- After unzipping, check the extracted text file for the flag.
```

Key takeaways from the instructions:
- The flag is stored inside a ZIP archive
- The archive is **split across multiple part files** (`part_aa` through `part_ae`)
- The ZIP is **password protected** with the password `supersecret`

---

## Step 1 – Reconstruct the Archive

The split parts were reassembled into a single file using `cat`:

```bash
$ cat part_aa part_ab part_ac part_ad part_ae > combined_files
```

> **Why `cat`?** When large files are split with tools like `split`, they are stored as sequential binary fragments. `cat` concatenates them in order, recreating the original byte stream.

---

## Step 2 – Identify the File Type

Before attempting extraction, the file type was verified using `file` to avoid guessing:

```bash
$ file combined_files
```

```
combined_files: Zip archive data, at least v1.0 to extract
```

This confirmed the reconstructed file was a valid ZIP archive.

---

## Step 3 – Extract the ZIP Archive

The archive was extracted using `unzip` with the password from `instructions.txt`:

```bash
$ unzip combined_files
```

```
Archive:  combined_files
[combined_files] flag.txt password:
 extracting: flag.txt
```

Password entered: `supersecret`

---

## Step 4 – Retrieve the Flag

```bash
$ cat flag.txt
```

```
picoCTF{z1p_and_spl1t_f1l3s_4r3_fun_2d6c5d3f}
```

---

<img width="593" height="770" alt="Screenshot 2026-06-06 161256" src="https://github.com/user-attachments/assets/298e06a5-fee5-433e-869a-9ab47aab8720" />


## Summary

| Step | Command | Purpose |
|------|---------|---------|
| Inspect directory | `ls -la` | Identify available files |
| Read instructions | `grep -r "zip" instructions.txt` | Understand the challenge structure |
| Reconstruct archive | `cat part_* > combined_files` | Reassemble split fragments |
| Identify file type | `file combined_files` | Confirm it is a ZIP before extracting |
| Extract archive | `unzip combined_files` | Decompress with password `supersecret` |
| Read flag | `cat flag.txt` | Retrieve the final flag |

---

## Key Concepts

- **File splitting & reconstruction** — Large files are often split for storage or transmission. `split` divides them; `cat` joins them back in order.
- **File type identification** — Never trust file extensions alone. `file` reads the magic bytes header to report the true format.
- **Password-protected archives** — `unzip` supports encrypted ZIP extraction; the password is passed interactively or via the `-P` flag.
- **Linux CLI fundamentals** — Directory traversal, file inspection, and archive handling are core SOC and forensics skills.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `ls -la` | List all files with permissions and timestamps |
| `cat` | Concatenate binary file fragments |
| `file` | Identify file type via magic bytes |
| `unzip` | Extract password-protected ZIP archives |
| `grep` | Search file contents for keywords |

---
