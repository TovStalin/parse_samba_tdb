import binascii
import argparse
import logging
import re
from colorama import Fore, Style
from typing import Set, Tuple, Optional
logger = logging.getLogger("parse_samba_tdb")


def get_samba_creds(filedata: bytes) -> Optional[Set[Tuple[str, str]]]:
    ''' Trying to extract nt and lm hashes from file, gained in args "filename" and returned set of tuples Set((username, 'nt_hash:lm_hash')) (also Set((username, 'nt_hash))) or None if filedata didn't contains a credentials '''
    user_list = set() # set of finding credentials
    try:
        curr_index = filedata.index(b'USER_')
    except ValueError:
        logger.warning(Fore.YELLOW + f"Thus file didn't contain a credentail" + Style.RESET_ALL)
        return None
    logger.info(Fore.BLUE + "Start parse filedata" + Style.RESET_ALL)
    while curr_index != -1:
        filedata = filedata[curr_index + 5::]
        username = ''
        for item in filedata:
            if item != 0:
                username += chr(item)
            else:
                break
        filedata = filedata[len(username)::]
        pattern = b"\x00\x00\x00\x00\x00........\x00\x00\x00\x00"
        if re.match(pattern, filedata, re.DOTALL):
            filedata = filedata[17::]
        else:
            logger.error(Fore.RED + "Error when parsing file. Try tdbdump (from tdbtool) on this file" + Style.RESET_ALL)
            return None
        nix = filedata.index(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00")
        if nix > 0:
            nix += 16
            filedata = filedata[nix::]
        else:
            logger.error(Fore.RED + "Error when parsing file. Try tdbdump (from tdbtool) on this file" + Style.RESET_ALL)
            return None
        nix = filedata.index(b"\x10\x00\x00\x00")
        if nix > 0:
            nix += 4
            filedata = filedata[nix::]
        nix = filedata.index(b"\x00\x00\x00\x00")
        if nix > 0:
            if nix == 16:
                ntlm_hash = binascii.hexlify(filedata[:16:]).decode('utf8')
            elif nix == 36:
                nt_hash = binascii.hexlify(filedata[:16:]).decode('utf8')
                lm_hash = binascii.hexlify(filedata[20:36:]).decode('utf8')
                ntlm_hash = nt_hash + ":" + lm_hash
        else:
            logger.error(Fore.RED + "Error when parsing file. Try tdbdump (from tdbtool) on this file" + Style.RESET_ALL)
            return None
        new_user_data = (username, ntlm_hash)
        if new_user_data not in user_list:
            logger.info(Fore.GREEN + f"Finding data for {username}:{ntlm_hash}" + Style.RESET_ALL)
        user_list.add((username, ntlm_hash))
        try:
            curr_index = filedata.index(b'USER_')
        except ValueError:
            curr_index = -1
    logger.info(Fore.BLUE + "End parse of data" + Style.RESET_ALL)
    return user_list


def main():
    logging.basicConfig(level=logging.INFO)
    argument_parser = argparse.ArgumentParser(description="Tool for parse samba secret file (default location - /var/lib/samba/private/passdb.tdb) and print all finding username:ntlm_hash")
    argument_parser.add_argument('-f', '--filename', help="Filename with samba secrets (in tdb format) to parse", default='/var/lib/samba/private/passdb.tdb', type=str, required=False)

    args = argument_parser.parse_args()
    try:
        logger.info(Fore.BLUE + f"Trying to open file '{args.filename}'" + Style.RESET_ALL)
        with open(args.filename, 'rb') as f:
            get_samba_creds(f.read())
    except FileNotFoundError:
        logger.error(Fore.RED + f"File {args.filename} not found!" + Style.RESET_ALL)
    except PermissionError:
        logger.error(Fore.RED + "Error when parsing file: Permission Denied!" + Style.RESET_ALL)


if __name__ == '__main__':
    main()