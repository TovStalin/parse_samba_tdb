# Parse_samba_tdb

Red Team tool for parse and extract username:ntlm_hash from samba secret file (default location - /var/lib/samba/private/passdb.tdb)

## Usage:
First of all, we need to install package:
```bash
python -m venv ./venv
source ./venv/bin/activate
pip install git+https://github.com/TovStalin/parse_samba_tdb
```

From now, we can call the tool on file like this:

```bash
parse_samba_tdb -f <filename>
```
Where:
- `-f <filename>` - file to extract creds. By default - `/var/lib/samba/private/passdb.tdb`.

Example:

```bash
parse_samba_tdb ./passdb.tdb
```

## Package functionality

Use this utility like a package:
```python
# Preparation

with open('./passdb.tdb', 'rb') as f:
    filedata = f.read()

# import the module
import parse_samba_tdb
# parsing file
creds = parse_samba_tdb.get_samba_creds(filedata)
```
Output of this function is set of tuple(username, 'nt:lm hash') (Set\[Tuple\[str, str\]\]), contained in this data.
