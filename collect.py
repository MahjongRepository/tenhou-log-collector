import glob
import os
import sys
from optparse import OptionParser
from struct import Struct
from urllib.parse import parse_qs, unquote
from urllib.request import urlopen
from urllib.error import HTTPError
import struct
import codecs


def tenhou_hash(log_id):
    table = [
        22136, 52719, 55146, 42104, 59591, 46934, 9248,  28891,
        49597, 52974, 62844, 4015, 18311, 50730, 43056, 17939,
        64838, 38145, 27008, 39128, 35652, 63407, 65535, 23473,
        35164, 55230, 27536, 4386, 64920, 29075, 42617, 17294, 18868, 2081
    ]

    code_pos = log_id.rindex("-") + 1
    code = log_id[code_pos:]
    if code[0] == 'x':
        a, b, c = struct.unpack(">HHH", bytes.fromhex(code[1:]))
        index = 0
        if log_id[:12] > "2010041111gm":
            x = int("3" + log_id[4:10])
            y = int(log_id[9])
            index = x % (33 - y)
        first = (a ^ b ^ table[index]) & 0xFFFF
        second = (b ^ c ^ table[index] ^ table[index + 1]) & 0xFFFF
        return log_id[:code_pos] + codecs.getencoder('hex_codec')(struct.pack(">HH", first, second))[0].decode('ASCII')
    else:
        return log_id


def prepare_sol_files():
    results = []

    chrome_directories = [
        # linux
        '.config/chromium/*/',
        '.config/google-chrome/*/',
        # mac os
        'Library/Application Support/Google/Chrome/*/',
        # windows
        'AppData/Local/Google/Chrome/User Data/*/'
    ]

    for directory in chrome_directories:
        results.extend(glob.glob(os.path.join(
            os.path.expanduser('~'),
            '{0}/Pepper Data/Shockwave Flash/WritableRoot/#SharedObjects/*/mjv.jp/mjinfo.sol'.format(directory))
        ))

    # FireFox?
    results.extend(glob.glob(os.path.join(
        os.path.expanduser('~'),
        '.macromedia/Flash_Player/#SharedObjects/*/mjv.jp/mjinfo.sol')))

    return results


def extract_logs_from_windows_client():
    config_path = os.path.join(os.path.expanduser('~'), 'AppData/Local/C-EGG/tenhou/130/config.ini')
    if not os.path.exists(config_path):
        return []

    with open(config_path, 'rb') as f:
        data = f.read().decode('ASCII')

    logs = data.split('[LOG]')[1].split()
    # first items is not log entity, so let's cut it
    logs = logs[1:]

    results = []
    # remove index number from log entity
    for log in logs:
        log = log.split('=')
        results.append('='.join(log[1:]))

    return results


def parse_sol_files(sol_files):
    results = []
    for sol_file in sol_files:
        print("Reading Flash state file: {0}\n".format(sol_file))
        with open(sol_file, 'rb') as f:
            data = f.read()

        # What follows is a limited parser for Flash Local Shared Object files -
        # a more complete implementation may be found at:
        # https://pypi.python.org/pypi/PyAMF
        header = Struct('>HI10s8sI')
        magic, objlength, magic2, mjinfo, padding = header.unpack_from(data)
        offset = header.size
        assert magic == 0xbf
        assert magic2 == b'TCSO\0\x04\0\0\0\0'
        assert mjinfo == b'\0\x06mjinfo'
        assert padding == 0
        ushort = Struct('>H')
        ubyte = Struct('>B')
        while offset < len(data):
            length, = ushort.unpack_from(data, offset)
            offset += ushort.size
            name = data[offset:offset+length]
            offset += length
            amf0_type, = ubyte.unpack_from(data, offset)
            offset += ubyte.size
            # Type 2: UTF-8 String, prefixed with 2-byte length
            if amf0_type == 2:
                length, = ushort.unpack_from(data, offset)
                offset += ushort.size
                value = data[offset:offset+length]
                offset += length
            # Type 6: Undefined
            elif amf0_type == 6:
                value = None
            # Type 1: Boolean
            elif amf0_type == 1:
                value = bool(data[offset])
                offset += 1
            # Other types from the AMF0 specification are not implemented, as they
            # have not been observed in mjinfo.sol files. If required, see
            # http://download.macromedia.com/pub/labs/amf/amf0_spec_121207.pdf
            else:
                print("Unimplemented AMF0 type {} at offset={} (hex {})".format(amf0_type, offset, hex(offset)))
            trailer_byte = data[offset]
            assert trailer_byte == 0
            offset += 1
            if name == b'logstr':
                results = filter(None, value.split(b'\n'))

        results = [i.decode('ASCII') for i in results]

    return results


def download_logs(directory, results):
    for log_id in results:
        log_name = parse_qs(log_id)['file'][0]
        hashed_log_name = tenhou_hash(log_name)

        # save file with original name
        target_fname = os.path.join(directory, "{}.xml".format(log_name))

        if os.path.exists(target_fname):
            print("Game {} already downloaded".format(hashed_log_name))
        else:
            print("Downloading game {}".format(hashed_log_name))
            try:
                response = urlopen('http://e.mjv.jp/0/log/?{0}'.format(hashed_log_name))
                data = response.read()
                with open(target_fname, 'wb') as f:
                    f.write(data)
            except HTTPError as e:
                if e.code == 404:
                    print("Could not download game {}. Is the game still in progress?".format(hashed_log_name))
                else:
                    raise


def main():
    attrs = OptionParser()
    attrs.add_option('-d', '--directory',
                     help='Directory to store downloaded XML. If empty, script will not to do downloads')
    attrs.add_option('-m', '--meta',
                     default=os.path.join(os.path.expanduser('~'), 'tenhou-meta.txt'),
                     help='File for store meta information')

    opts, args = attrs.parse_args()
    if args:
        attrs.error('This command takes no positional arguments')

    sol_files = prepare_sol_files()

    results = parse_sol_files(sol_files)
    is_windows = sys.platform.startswith('win')
    if is_windows:
        results += extract_logs_from_windows_client()

    # let's decode lines
    results = [unquote(i) for i in results]

    old_data = []
    if os.path.exists(opts.meta):
        with open(opts.meta, 'r', encoding='utf-8') as f:
            old_data = f.read().split('\n')

    new_logs = list(set(results) - set(old_data))

    if new_logs:
        with open(opts.meta, 'a', encoding='utf-8') as f:
            # we append old file, need to add new line
            if old_data:
                f.write('\n')
            f.write('\n'.join(new_logs))

        print('Added {0} new logs'.format(len(new_logs)))

        if opts.directory:
            if not os.path.exists(opts.directory):
                os.makedirs(opts.directory)

            download_logs(opts.directory, new_logs)
    else:
        print('Nothing to add')

if __name__ == '__main__':
    main()
