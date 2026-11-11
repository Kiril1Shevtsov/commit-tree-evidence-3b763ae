#!/usr/bin/env python3
"""Offline fixed-object signature, Git, archive and member byte verifier. Python 3.9+."""
import argparse
import base64
import binascii
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import io
import stat
import zipfile

HERE = Path(__file__).resolve().parent
FINGERPRINT = '968479A1AFF927E37D1A566BB5690EEEBB952194'
COMMIT_OID = '3b763ae9202b098d976ee91a36c1c19e0adfaff9'
TREE_OID = '582704406da2164f088c3ef9bcd40b0785a3fa52'
MANIFEST_OID = 'd6759539a874d183459ca65bbede7643372199dd'
SIGNED_TIME = '2026-11-08T15:26:20Z'
ARCHIVE_COMMITMENT_SHA256 = '2d8c3bb20d248cb604ae7aa74fe4fbe7c47b9b7383f54a1497cb824d3dc9b72d'
ARCHIVE_COMMITMENT_BYTES = 775892
INPUTS = {
    'evidence/commit.raw': (1309, '95f59c8ff2d8b493de9f9678143690a7f653aad3bce80eb2294a8114dc0f8f9f'),
    'evidence/root.tree': (862, '21d130edd1f8b7b9879268630d43c496d82a2d03a988366b4c2c14d800ef6db0'),
    'evidence/manifest.json': (224518, 'f0f0f7ae2bbf3ce0e07d960745d5fcf7b00609de166dd9c4ae8e5ad1323257cf'),
    'verification/github-web-flow.asc': (2483, 'cee5d9d22b4e29eaa57ce1dd0dcadfe6e93920efe57b2adedc93a49641c97847'),
}
class Rejected(Exception):
    """Only constant, non-sensitive reason codes may be used here."""


def need(ok, code):
    if not ok:
        raise Rejected(code)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def git_oid(kind, b):
    return hashlib.sha1(kind.encode('ascii') + b' ' + str(len(b)).encode('ascii') + b'\0' + b).hexdigest()


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result, 'JSON_DUPLICATE_KEY')
        result[k] = v
    return result


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(Rejected('JSON_NONFINITE')))



def packet_length(data, pos):
    need(pos < len(data), 'PACKET_TRUNCATED')
    lead = data[pos]
    if lead < 192:
        return lead, pos + 1
    if lead < 224:
        need(pos + 1 < len(data), 'PACKET_TRUNCATED')
        return (lead - 192) * 256 + data[pos + 1] + 192, pos + 2
    if lead == 255:
        need(pos + 5 <= len(data), 'PACKET_TRUNCATED')
        return int.from_bytes(data[pos + 1:pos + 5], 'big'), pos + 5
    raise Rejected('PARTIAL_PACKET_UNSUPPORTED')


def packets(data):
    result, pos = [], 0
    while pos < len(data):
        lead = data[pos]
        need(lead & 128, 'INVALID_PACKET_HEADER')
        pos += 1
        if lead & 64:
            tag = lead & 63
            length, pos = packet_length(data, pos)
        else:
            tag, lt = (lead >> 2) & 15, lead & 3
            need(lt != 3, 'INDEFINITE_PACKET_UNSUPPORTED')
            size = (1, 2, 4)[lt]
            need(pos + size <= len(data), 'PACKET_TRUNCATED')
            length = int.from_bytes(data[pos:pos + size], 'big')
            pos += size
        need(pos + length <= len(data), 'PACKET_TRUNCATED')
        result.append((tag, data[pos:pos + length]))
        pos += length
    return result


def crc24(data):
    crc = 0xB704CE
    for octet in data:
        crc ^= octet << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return (crc & 0xFFFFFF).to_bytes(3, 'big')


def dearmor(armored):
    lines = armored.decode('ascii').splitlines()
    need(bool(lines), 'INVALID_ARMOR')
    labels = {'-----BEGIN PGP PUBLIC KEY BLOCK-----': '-----END PGP PUBLIC KEY BLOCK-----',
              '-----BEGIN PGP SIGNATURE-----': '-----END PGP SIGNATURE-----'}
    need(lines[0] in labels and lines[-1] == labels.get(lines[0]), 'INVALID_ARMOR')
    need(len(lines) >= 4, 'INVALID_ARMOR_HEADERS')
    start = 2 if lines[1] == '' else 1
    checksum = lines[-2]
    need(checksum.startswith('=') and len(checksum) == 5, 'ARMOR_CRC_MISSING')
    body = lines[start:-2]
    need(bool(body) and all(re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', x) for x in body),
         'INVALID_ARMOR_BASE64')
    data = base64.b64decode(''.join(body), validate=True)
    need(base64.b64decode(checksum[1:], validate=True) == crc24(data), 'ARMOR_CRC_MISMATCH')
    return data


def mpi(data, pos, fixed_signature_width=False):
    need(pos + 2 <= len(data), 'MPI_TRUNCATED')
    bits = int.from_bytes(data[pos:pos + 2], 'big')
    size = (bits + 7) // 8
    pos += 2
    need(pos + size <= len(data), 'MPI_TRUNCATED')
    value = int.from_bytes(data[pos:pos + size], 'big')
    # These existing GitHub signatures encode a fixed 4096-bit MPI even
    # when the value has leading zero bits. GnuPG accepts this representation.
    need((bits == 4096 and 0 < value.bit_length() <= bits) if fixed_signature_width
         else value.bit_length() == bits, 'MPI_NONCANONICAL')
    return value, pos + size


def public_key(armored):
    pp = [body for tag, body in packets(dearmor(armored)) if tag == 6]
    pp = [b for b in pp if len(b) <= 65535 and
          hashlib.sha1(b'\x99' + len(b).to_bytes(2, 'big') + b).hexdigest().upper() == FINGERPRINT]
    need(len(pp) == 1, 'KEY_PRIMARY_COUNT')
    b = pp[0]
    need(len(b) >= 8 and b[0] == 4 and b[5] == 1, 'KEY_FORMAT_UNSUPPORTED')
    fp = hashlib.sha1(b'\x99' + len(b).to_bytes(2, 'big') + b).hexdigest().upper()
    need(fp == FINGERPRINT, 'KEY_FINGERPRINT_MISMATCH')
    n, pos = mpi(b, 6)
    e, pos = mpi(b, pos)
    need(pos == len(b) and n.bit_length() == 4096 and e == 65537, 'KEY_PARAMETERS')
    return n, e


def subpackets(data):
    pos, out = 0, []
    while pos < len(data):
        size, pos = packet_length(data, pos)
        need(size >= 1 and pos + size <= len(data), 'SUBPACKET_TRUNCATED')
        kind = data[pos]
        # This predicate deliberately supports only this fixed signature profile.
        need((kind & 127) in (2, 16, 33) or not kind & 128, 'UNKNOWN_CRITICAL_SUBPACKET')
        out.append((kind & 127, data[pos + 1:pos + size]))
        pos += size
    return out


def verify_signature(payload, signature, key):
    pp = packets(dearmor(signature))
    need(len(pp) == 1 and pp[0][0] == 2, 'SIGNATURE_PACKET_COUNT')
    b = pp[0][1]
    need(len(b) >= 12 and b[:4] == b'\x04\x00\x01\x08', 'SIGNATURE_PROFILE')
    length = int.from_bytes(b[4:6], 'big')
    end = 6 + length
    need(end + 2 <= len(b), 'SIGNATURE_TRUNCATED')
    sp = subpackets(b[6:end])
    times = [v for t, v in sp if t == 2]
    issuers = [v for t, v in sp if t == 16]
    need(len(times) == 1 and len(times[0]) == 4, 'HASHED_TIME_REQUIRED')
    need(len(issuers) == 1 and issuers[0].hex().upper() == FINGERPRINT[-16:],
         'HASHED_ISSUER_REQUIRED')
    ulen = int.from_bytes(b[end:end + 2], 'big')
    pos = end + 2 + ulen
    need(pos + 2 <= len(b), 'SIGNATURE_TRUNCATED')
    for tag, val in subpackets(b[end + 2:pos]):
        if tag == 16:
            need(val.hex().upper() == FINGERPRINT[-16:], 'ISSUER_CONFLICT')
    header = b[:end]
    digest = hashlib.sha256(payload + header + b'\x04\xff' + len(header).to_bytes(4, 'big')).digest()
    need(b[pos:pos + 2] == digest[:2], 'SIGNATURE_HASH_PREFIX_MISMATCH')
    sig, final = mpi(b, pos + 2, fixed_signature_width=True)
    n, e = key
    need(final == len(b) and 0 < sig < n, 'SIGNATURE_MPI_INVALID')
    der = bytes.fromhex('3031300d060960864801650304020105000420') + digest
    k = (n.bit_length() + 7) // 8
    expected = b'\x00\x01' + b'\xff' * (k - len(der) - 3) + b'\x00' + der
    need(pow(sig, e, n).to_bytes(k, 'big') == expected, 'RSA_SIGNATURE_INVALID')
    epoch = int.from_bytes(times[0], 'big')
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def read_bounded(path, maximum):
    need(path.is_file() and not path.is_symlink(), 'INPUT_MISSING_OR_NOT_REGULAR')
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    need(len(data) <= maximum, 'INPUT_TOO_LARGE')
    return data


def split_signed_commit(raw):
    need(b'\r' not in raw, 'COMMIT_CR_NOT_SUPPORTED')
    header, sep, message = raw.partition(b'\n\n')
    need(sep == b'\n\n', 'COMMIT_HEADER_SEPARATOR')
    lines = header.split(b'\n')
    starts = [i for i, x in enumerate(lines) if x.startswith(b'gpgsig ')]
    need(len(starts) == 1, 'COMMIT_SIGNATURE_COUNT')
    i = starts[0]
    need(i > 0 and all(x.startswith(b' ') for x in lines[i + 1:]), 'COMMIT_SIGNATURE_POSITION')
    pre = lines[:i]
    need(len(pre) == 4 and pre[0] == b'tree ' + TREE_OID.encode('ascii')
         and pre[1].startswith(b'parent ') and pre[2].startswith(b'author ')
         and pre[3].startswith(b'committer '), 'COMMIT_HEADER_PROFILE')
    need(re.fullmatch(rb'parent [0-9a-f]{40}', pre[1]) is not None, 'COMMIT_PARENT_FORMAT')
    signature = b'\n'.join([lines[i][7:]] + [x[1:] for x in lines[i + 1:]])
    payload = b'\n'.join(pre) + b'\n\n' + message
    rebuilt = b'\n'.join(pre) + b'\ngpgsig ' + signature.replace(b'\n', b'\n ') + b'\n\n' + message
    need(rebuilt == raw, 'COMMIT_RECONSTRUCTION')
    return payload, signature


def parse_tree(raw):
    pos, rows, names, order = 0, [], set(), []
    while pos < len(raw):
        end = raw.find(b'\0', pos)
        need(end >= pos and end + 21 <= len(raw), 'TREE_TRUNCATED')
        prefix = raw[pos:end].split(b' ', 1)
        need(len(prefix) == 2, 'TREE_ENTRY_FORMAT')
        mode, name = prefix
        need(mode in (b'100644', b'100755', b'40000', b'120000', b'160000'), 'TREE_MODE')
        need(name and name not in (b'.', b'..') and b'/' not in name and b'\\' not in name,
             'TREE_NAME_INVALID')
        need(name not in names, 'TREE_DUPLICATE_NAME')
        names.add(name)
        order.append(name + (b'/' if mode == b'40000' else b''))
        rows.append({'mode': mode.decode('ascii'), 'name': name.decode('utf-8'),
                     'oid': raw[end + 1:end + 21].hex()})
        pos = end + 21
    need(order == sorted(order), 'TREE_ORDER')
    return rows


def verify_manifest_commitment(raw):
    manifest = strict_json(raw)
    need(isinstance(manifest, dict), 'MANIFEST_STRUCTURE')
    artifacts = manifest.get('artifacts')
    need(isinstance(artifacts, list) and len(artifacts) == 175
         and all(isinstance(r, dict) for r in artifacts), 'MANIFEST_RECORDS')
    selected = [(i, r) for i, r in enumerate(artifacts)
                if r.get('original_sha256') == ARCHIVE_COMMITMENT_SHA256]
    need(len(selected) == 1 and selected[0][0] == 54, 'MANIFEST_TARGET_COUNT_OR_INDEX')
    index, record = selected[0]
    need(record.get('name') == 'rademacher_full_max_analytic_release_20261108.zip'
         and record.get('stored_name') == record['name'], 'MANIFEST_TARGET_NAME')
    need(record.get('stored_sha256') == ARCHIVE_COMMITMENT_SHA256, 'MANIFEST_STORED_HASH')
    need(all(type(record.get(k)) is int and record[k] == ARCHIVE_COMMITMENT_BYTES
             for k in ('original_bytes', 'stored_bytes')), 'MANIFEST_TARGET_SIZE')
    need(record.get('backup_form') == 'exact-original-bytes' and record.get('source_exclusions') == [],
         'MANIFEST_TARGET_FORM')
    expected_transport = [{'volume': 'RESEARCH_20261108_PART_003.zip',
          'entry': 'rademacher/rademacher_full_max_analytic_release_20261108.zip',
          'bytes': ARCHIVE_COMMITMENT_BYTES, 'sha256': ARCHIVE_COMMITMENT_SHA256}]
    need(record.get('transport_parts') == expected_transport, 'MANIFEST_TARGET_TRANSPORT')
    return {'artifact_records': len(artifacts),
            'target_record_index_zero_based': index,
            'archive_sha256': ARCHIVE_COMMITMENT_SHA256,
            'archive_bytes': ARCHIVE_COMMITMENT_BYTES}


ARCHIVE_NAME = 'rademacher_full_max_analytic_release_20261108.zip'
ARCHIVE_ROOT = ARCHIVE_NAME[:-4] + '/'
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 16000000
MAX_TOTAL_BYTES = 64000000


def safe_member(name):
    need(isinstance(name, str) and name and not name.startswith('/')
         and '\\' not in name and ':' not in name and '\0' not in name
         and all(p not in ('', '.', '..') for p in name.rstrip('/').split('/')),
         'ZIP_UNSAFE_PATH')


def archive_members(raw):
    need(len(raw) <= 2000000, 'ZIP_INPUT_LIMIT')
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        rows = z.infolist()
        need(len(rows) <= MAX_MEMBERS, 'ZIP_MEMBER_LIMIT')
        total = 0
        seen = set()
        for row in rows:
            name = row.filename
            need(name == row.orig_filename, 'ZIP_TRUNCATED_NAME')
            safe_member(name)
            need(name.rstrip('/') not in seen, 'ZIP_DUPLICATE_MEMBER')
            seen.add(name.rstrip('/'))
            mode = row.external_attr >> 16
            need(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'ZIP_SPECIAL_FILE')
            need(not row.flag_bits & 1, 'ZIP_ENCRYPTED_MEMBER')
            need(row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'ZIP_COMPRESSION')
            need(row.file_size <= MAX_MEMBER_BYTES, 'ZIP_MEMBER_SIZE_LIMIT')
            total += row.file_size
            need(total <= MAX_TOTAL_BYTES, 'ZIP_TOTAL_SIZE_LIMIT')
            with z.open(row) as stream:
                content = stream.read(MAX_MEMBER_BYTES + 1)
                need(len(content) == row.file_size, 'ZIP_MEMBER_SIZE')
            need(binascii.crc32(content) & 0xffffffff == row.CRC, 'ZIP_CRC')
            if not row.is_dir():
                result[name] = content
    return result


def verify_internal_manifest(members):
    manifest_name = ARCHIVE_ROOT + 'MANIFEST.json'
    need(manifest_name in members, 'ARCHIVE_MANIFEST_MISSING')
    m = strict_json(members[manifest_name])
    need(isinstance(m, dict) and m.get('manifest_self_excluded') is True,
         'ARCHIVE_MANIFEST_STRUCTURE')
    files = m.get('files')
    need(isinstance(files, dict) and files, 'ARCHIVE_MANIFEST_FILES')
    expected = {manifest_name}
    document_count = 0
    for name, row in files.items():
        safe_member(name)
        target = ARCHIVE_ROOT + name
        need(isinstance(row, dict) and type(row.get('bytes')) is int
             and isinstance(row.get('sha256'), str)
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'ARCHIVE_MANIFEST_RECORD')
        need(target in members, 'ARCHIVE_MEMBER_MISSING')
        content = members[target]
        need(len(content) == row['bytes'], 'ARCHIVE_MEMBER_LENGTH')
        need(sha256(content) == row['sha256'], 'ARCHIVE_MEMBER_HASH')
        expected.add(target)
        if name.lower().endswith(('.md', '.txt', '.pdf', '.tex', '.docx')):
            document_count += 1
    need(expected == set(members), 'ARCHIVE_MANIFEST_COVERAGE')
    return {'member_files': len(members), 'manifest_hash_records_checked': len(files),
            'document_files_hash_checked': document_count,
            'manifest_bytes_bound_by_whole_archive_hash': True,
            'internal_metadata_semantics_verified': False}


def verify_archive(raw):
    need(len(raw) == ARCHIVE_COMMITMENT_BYTES, 'ARCHIVE_LENGTH')
    need(sha256(raw) == ARCHIVE_COMMITMENT_SHA256, 'ARCHIVE_HASH')
    return verify_internal_manifest(archive_members(raw))


def check_sums(base):
    raw = read_bounded(base / 'SHA256SUMS', 100000)
    rows, seen = [], set()
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)', line)
        need(match is not None, 'CHECKSUM_FORMAT')
        digest, name = match.groups()
        need(name not in seen and not name.startswith('/') and all(p not in ('', '.', '..')
             for p in name.split('/')) and name != 'SHA256SUMS', 'CHECKSUM_PATH')
        seen.add(name)
        path = base / name
        need(base.resolve() in path.resolve().parents, 'CHECKSUM_PATH_ESCAPE')
        need(sha256(read_bounded(path, 2000000)) == digest, 'CHECKSUM_MISMATCH')
        rows.append(name)
    need((set(INPUTS) | {'evidence/' + ARCHIVE_NAME}).issubset(seen) and 'verify.py' in seen, 'CHECKSUM_REQUIRED_FILES')
    return len(rows)


def verify(base):
    data = {}
    for name, (length, digest) in INPUTS.items():
        b = read_bounded(base / name, length)
        need(len(b) == length, 'INPUT_SIZE_MISMATCH')
        need(sha256(b) == digest, 'INPUT_SHA256_MISMATCH')
        data[name] = b
    commit, tree, manifest = (data['evidence/' + n] for n in ('commit.raw', 'root.tree', 'manifest.json'))
    need(git_oid('commit', commit) == COMMIT_OID, 'COMMIT_GIT_OID_MISMATCH')
    need(git_oid('tree', tree) == TREE_OID, 'TREE_GIT_OID_MISMATCH')
    need(git_oid('blob', manifest) == MANIFEST_OID, 'MANIFEST_GIT_OID_MISMATCH')
    payload, signature = split_signed_commit(commit)
    key = public_key(data['verification/github-web-flow.asc'])
    signed_time = verify_signature(payload, signature, key)
    need(signed_time == SIGNED_TIME, 'SIGNED_TIME_MISMATCH')
    entries = parse_tree(tree)
    need(len(entries) == 17, 'ROOT_ENTRY_COUNT')
    matches = [r for r in entries if r['name'] == 'RESEARCH_20261108_MANIFEST.json']
    need(matches == [{'mode': '100644', 'name': 'RESEARCH_20261108_MANIFEST.json',
                      'oid': MANIFEST_OID}], 'ROOT_MANIFEST_BINDING')
    recorded = verify_manifest_commitment(manifest)
    archive = read_bounded(base / 'evidence' / ARCHIVE_NAME, ARCHIVE_COMMITMENT_BYTES)
    archive_result = verify_archive(archive)
    return {'status': 'PASS', 'scope': 'signed_commit_to_archive_and_member_bytes',
            'commit_oid': COMMIT_OID, 'root_tree_oid': TREE_OID, 'manifest_blob_oid': MANIFEST_OID,
            'git_object_headers_included_in_sha1': True, 'all_three_object_ids_valid': True,
            'input_sha256_pins_valid': True, 'rsa_4096_pkcs1_v1_5_sha256_valid': True,
            'pinned_key_fingerprint': FINGERPRINT, 'armor_crc24_valid': True,
            'hashed_signature_creation_time_utc': signed_time,
            'root_entries': len(entries), 'manifest_membership_valid': True,
            'manifest_commitment': recorded, 'archive_verification': archive_result,
            'limitations': ['signature_date_is_a_signed_field_not_a_trusted_timestamp',
                            'historical_key_custody_not_verified',
                            'mathematical_correctness_not_checked',
                            'archive_scripts_not_executed']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=HERE, help='Unpacked package root')
    parser.add_argument('--check-sums', action='store_true', help='Also check listed package files')
    args = parser.parse_args()
    try:
        result = verify(args.directory)
        if args.check_sums:
            result['package_checksum_files_checked'] = check_sums(args.directory)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except Rejected as error:
        print(json.dumps({'status': 'FAIL', 'code': str(error)}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError, binascii.Error, zipfile.BadZipFile, RuntimeError):
        print(json.dumps({'status': 'FAIL', 'code': 'MALFORMED_OR_UNREADABLE_INPUT'}))
        return 1
    except Exception:
        print(json.dumps({'status': 'ERROR', 'code': 'UNEXPECTED_INTERNAL_ERROR'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
