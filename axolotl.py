#! /usr/bin/python
from ctypes import *
import json

lib = cdll.LoadLibrary("build/libaxolotl.so")


lib.axolotl_error.argtypes = []
lib.axolotl_error.restypes = c_size_t

ERR = lib.axolotl_error()

class AxolotlError(Exception):
    pass


lib.axolotl_account_size.argtypes = []
lib.axolotl_account_size.restype = c_size_t

lib.axolotl_account.argtypes = [c_void_p]
lib.axolotl_account.restype = c_void_p

lib.axolotl_account_last_error.argtypes = [c_void_p]
lib.axolotl_account_last_error.restype = c_char_p

def account_errcheck(res, func, args):
    if res == ERR:
        raise AxolotlError("%s: %s" % (
            func.__name__, lib.axolotl_account_last_error(args[0])
        ))
    return res


def account_function(func, *types):
    func.argtypes = (c_void_p,) + types
    func.restypes = c_size_t
    func.errcheck = account_errcheck


account_function(
    lib.axolotl_pickle_account, c_void_p, c_size_t, c_void_p, c_size_t
)
account_function(
    lib.axolotl_unpickle_account, c_void_p, c_size_t, c_void_p, c_size_t
)
account_function(lib.axolotl_create_account_random_length)
account_function(lib.axolotl_create_account, c_void_p, c_size_t)
account_function(lib.axolotl_account_identity_keys_length)
account_function(lib.axolotl_account_identity_keys, c_void_p, c_size_t)
account_function(lib.axolotl_account_one_time_keys_length)
account_function(lib.axolotl_account_one_time_keys, c_void_p, c_size_t)

def read_random(n):
    with open("/dev/urandom", "rb") as f:
        return f.read(n)

class Account(object):
    def __init__(self):
        self.buf = create_string_buffer(lib.axolotl_account_size())
        self.ptr = lib.axolotl_account(self.buf)

    def create(self):
        random_length = lib.axolotl_create_account_random_length(self.ptr)
        random = read_random(random_length)
        random_buffer = create_string_buffer(random)
        lib.axolotl_create_account(self.ptr, random_buffer, random_length)

    def pickle(self, key):
        key_buffer = create_string_buffer(key)
        pickle_length = lib.axolotl_pickle_account_length(self.ptr)
        pickle_buffer = create_string_buffer(pickle_length)
        lib.axolotl_pickle_account(
            self.ptr, key_buffer, len(key), pickle_buffer, pickle_length
        )
        return pickle_buffer.raw

    def unpickle(self, key, pickle):
        key_buffer = create_string_buffer(key)
        pickle_buffer = create_string_buffer(pickle)
        lib.axolotl_unpickle_account(
            self.ptr, key_buffer, len(key), pickle_buffer, len(pickle)
        )

    def identity_keys(self):
        out_length = lib.axolotl_account_identity_keys_length(self.ptr)
        out_buffer = create_string_buffer(out_length)
        lib.axolotl_account_identity_keys(self.ptr, out_buffer, out_length)
        return json.loads(out_buffer.raw)

    def one_time_keys(self):
        out_length = lib.axolotl_account_one_time_keys_length(self.ptr)
        out_buffer = create_string_buffer(out_length)
        lib.axolotl_account_one_time_keys(self.ptr, out_buffer, out_length)
        return json.loads(out_buffer.raw)

    def clear(self):
        pass


lib.axolotl_session_size.argtypes = []
lib.axolotl_session_size.restype = c_size_t

lib.axolotl_session.argtypes = [c_void_p]
lib.axolotl_session.restype = c_void_p

lib.axolotl_session_last_error.argtypes = [c_void_p]
lib.axolotl_session_last_error.restype = c_char_p


def session_errcheck(res, func, args):
    if res == ERR:
        raise AxolotlError("%s: %s" % (
            func.__name__, lib.axolotl_session_last_error(args[0])
        ))
    return res


def session_function(func, *types):
    func.argtypes = (c_void_p,) + types
    func.restypes = c_size_t
    func.errcheck = session_errcheck

session_function(lib.axolotl_session_last_error)
session_function(
    lib.axolotl_pickle_session, c_void_p, c_size_t, c_void_p, c_size_t
)
session_function(
    lib.axolotl_unpickle_session, c_void_p, c_size_t, c_void_p, c_size_t
)
session_function(lib.axolotl_create_outbound_session_random_length)
session_function(
    lib.axolotl_create_outbound_session,
    c_void_p,  # Account
    c_void_p, c_size_t,  # Identity Key
    c_uint,  # One Time Key Id
    c_void_p, c_size_t,  # One Time Key
    c_void_p, c_size_t,  # Random
)
session_function(
    lib.axolotl_create_inbound_session,
    c_void_p,  # Account
    c_void_p, c_size_t,  # Pre Key Message
)
session_function(lib.axolotl_matches_inbound_session, c_void_p, c_size_t)
session_function(lib.axolotl_encrypt_message_type)
session_function(lib.axolotl_encrypt_random_length)
session_function(lib.axolotl_encrypt_message_length, c_size_t)
session_function(
    lib.axolotl_encrypt,
    c_void_p, c_size_t,  # Plaintext
    c_void_p, c_size_t,  # Random
    c_void_p, c_size_t,  # Message
);
session_function(
    lib.axolotl_decrypt_max_plaintext_length,
    c_size_t,  # Message Type
    c_void_p, c_size_t,  # Message
)
session_function(
    lib.axolotl_decrypt,
    c_size_t,  # Message Type
    c_void_p, c_size_t,  # Message
    c_void_p, c_size_t, # Plaintext
)

class Session(object):
    def __init__(self):
        self.buf = create_string_buffer(lib.axolotl_session_size())
        self.ptr = lib.axolotl_session(self.buf)

    def pickle(self, key):
        key_buffer = create_string_buffer(key)
        pickle_length = lib.axolotl_pickle_session_length(self.ptr)
        pickle_buffer = create_string_buffer(pickle_length)
        lib.axolotl_pickle_session(
            self.ptr, key_buffer, len(key), pickle_buffer, pickle_length
        )
        return pickle_buffer.raw

    def unpickle(self, key, pickle):
        key_buffer = create_string_buffer(key)
        pickle_buffer = create_string_buffer(pickle)
        lib.axolotl_unpickle_session(
            self.ptr, key_buffer, len(key), pickle_buffer, len(pickle)
        )

    def create_outbound(self, account, identity_key, one_time_key_id,
                        one_time_key):
        r_length = lib.axolotl_create_outbound_session_random_length(self.ptr)
        random = read_random(r_length)
        random_buffer = create_string_buffer(random)
        identity_key_buffer = create_string_buffer(identity_key)
        one_time_key_buffer = create_string_buffer(one_time_key)
        lib.axolotl_create_outbound_session(
            self.ptr,
            account.ptr,
            identity_key_buffer, len(identity_key),
            one_time_key_id,
            one_time_key_buffer, len(one_time_key),
            random_buffer, r_length
        )

    def create_inbound(self, account, one_time_key_message):
        one_time_key_message_buffer = create_string_buffer(one_time_key_message)
        lib.axolotl_create_inbound_session(
            self.ptr,
            account.ptr,
            one_time_key_message_buffer, len(one_time_key_message)
        )

    def matches_inbound(self, one_time_key_message):
        one_time_key_message_buffer = create_string_buffer(one_time_key_message)
        return bool(lib.axolotl_create_inbound_session(
            self.ptr,
            one_time_key_message_buffer, len(one_time_key_message)
        ))

    def encrypt(self, plaintext):
        r_length = lib.axolotl_encrypt_random_length(self.ptr)
        random = read_random(r_length)
        random_buffer = create_string_buffer(random)

        message_type = lib.axolotl_encrypt_message_type(self.ptr)
        message_length = lib.axolotl_encrypt_message_length(
            self.ptr, len(plaintext)
        )
        message_buffer = create_string_buffer(message_length)

        plaintext_buffer = create_string_buffer(plaintext)

        lib.axolotl_encrypt(
            self.ptr,
            plaintext_buffer, len(plaintext),
            random_buffer, r_length,
            message_buffer, message_length,
        )
        return message_type, message_buffer.raw

    def decrypt(self, message_type, message):
        message_buffer = create_string_buffer(message)
        max_plaintext_length = lib.axolotl_decrypt_max_plaintext_length(
            self.ptr, message_type, message_buffer, len(message)
        )
        plaintext_buffer = create_string_buffer(max_plaintext_length)
        message_buffer = create_string_buffer(message)
        plaintext_length = lib.axolotl_decrypt(
            self.ptr, message_type, message_buffer, len(message),
            plaintext_buffer, max_plaintext_length
        )
        return plaintext_buffer.raw[:plaintext_length]

    def clear(self):
        pass


if __name__ == '__main__':
    import argparse
    import sys
    import os
    import yaml

    parser = argparse.ArgumentParser()
    parser.add_argument("--key", help="Account encryption key", default="")
    commands = parser.add_subparsers()

    create_account = commands.add_parser("create_account", help="Create a new account")
    create_account.add_argument("account_file", help="Local account file")

    def do_create_account(args):
        if os.path.exists(args.account_file):
            sys.stderr.write("Account %r file already exists" % (
                args.account_file,
            ))
            sys.exit(1)
        account = Account()
        account.create()
        with open(args.account_file, "wb") as f:
            f.write(account.pickle(args.key))

    create_account.set_defaults(func=do_create_account)

    keys = commands.add_parser("keys", help="List public keys for an account")
    keys.add_argument("account_file", help="Local account_file")

    def do_keys(args):
        account = Account()
        with open(args.account_file, "rb") as f:
            account.unpickle(args.key, f.read())
        (r_id, id_key), (signed_id, signed_key) = account.identity_keys()
        ot_keys = account.one_time_keys()
        result1 = {
            "identityKey": str(id_key),
            "signedKey": {
                "keyId": signed_id,
                "publicKey": str(signed_key),
            },
            "lastResortKey": {
                "keyId": ot_keys[0][0],
                "publicKey": str(ot_keys[0][1]),
            },
        }
        result2 = {
            "oneTimeKeys": [{
                "keyId": k[0],
                "publicKey": str(k[1]),
            } for k in ot_keys[1:]]
        }
        try:
            yaml.dump(result1, sys.stdout, default_flow_style=False)
            yaml.dump(result2, sys.stdout, default_flow_style=False)
        except:
            pass

    keys.set_defaults(func=do_keys)

    outbound = commands.add_parser("outbound", help="Create an outbound session")
    outbound.add_argument("account_file", help="Local account file")
    outbound.add_argument("session_file", help="Local session file")
    outbound.add_argument("identity_key", help="Remote identity key")
    outbound.add_argument("signed_key_id", help="Remote signed key id",
                          type=int)
    outbound.add_argument("signed_key", help="Remote signed key")
    outbound.add_argument("one_time_key_id", help="Remote one time key id",
                          type=int)
    outbound.add_argument("one_time_key", help="Remote one time key")

    def do_outbound(args):
        if os.path.exists(args.session_file):
            sys.stderr.write("Session %r file already exists" % (
                args.account_file,
            ))
            sys.exit(1)
        account = Account()
        with open(args.account_file, "rb") as f:
            account.unpickle(args.key, f.read())
        session = Session()
        session.create_outbound(
            account, args.identity_key, args.signed_key_id, args.signed_key,
            args.one_time_key_id, args.one_time_key
        )
        with open(args.session_file, "wb") as f:
            f.write(session.pickle(args.key))

    outbound.set_defaults(func=do_outbound)

    def open_in(path):
        if path == "-":
            return sys.stdin
        else:
            return open(path, "rb")

    def open_out(path):
        if path == "-":
            return sys.stdout
        else:
            return open(path, "wb")

    inbound = commands.add_parser("inbound", help="Create an inbound session")
    inbound.add_argument("account_file", help="Local account file")
    inbound.add_argument("session_file", help="Local session file")
    inbound.add_argument("message_file", help="Message", default="-")
    inbound.add_argument("plaintext_file", help="Plaintext", default="-")

    def do_inbound(args):
        if os.path.exists(args.session_file):
            sys.stderr.write("Session %r file already exists" % (
                args.account_file,
            ))
            sys.exit(1)
        account = Account()
        with open(args.account_file, "rb") as f:
            account.unpickle(args.key, f.read())
        with open_in(args.message_file) as f:
            message_type = f.read(8)
            message = f.read()
        if message_type != "PRE_KEY ":
            sys.stderr.write("Expecting a PRE_KEY message")
            sys.exit(1)
        session = Session()
        session.create_inbound(account, message)
        plaintext = session.decrypt(0, message)
        with open(args.session_file, "wb") as f:
            f.write(session.pickle(args.key))
        with open_out(args.plaintext_file) as f:
            f.write(plaintext)

    inbound.set_defaults(func=do_inbound)

    encrypt = commands.add_parser("encrypt", help="Encrypt a message")
    encrypt.add_argument("session_file", help="Local session file")
    encrypt.add_argument("plaintext_file", help="Plaintext", default="-")
    encrypt.add_argument("message_file", help="Message", default="-")

    def do_encrypt(args):
        session = Session()
        with open(args.session_file, "rb") as f:
            session.unpickle(args.key, f.read())
        with open_in(args.plaintext_file) as f:
            plaintext = f.read()
        message_type, message = session.encrypt(plaintext)
        with open(args.session_file, "wb") as f:
            f.write(session.pickle(args.key))
        with open_out(args.message_file) as f:
            f.write(["PRE_KEY ", "MESSAGE "][message_type])
            f.write(message)

    encrypt.set_defaults(func=do_encrypt)

    decrypt = commands.add_parser("decrypt", help="Decrypt a message")
    decrypt.add_argument("session_file", help="Local session file")
    decrypt.add_argument("plaintext_file", help="Plaintext", default="-")
    decrypt.add_argument("message_file", help="Message", default="-")

    def do_decrypt(args):
        session = Session()
        with open(args.session_file, "rb") as f:
            session.unpickle(args.key, f.read())
        with open_in(args.message_file) as f:
            message_type = f.read(8)
            message = f.read()
        if message_type not in {"PRE_KEY ", "MESSAGE "}:
            sys.stderr.write("Expecting a PRE_KEY or MESSAGE message")
            sys.exit(1)
        message_type = 1 if message_type == "MESSAGE " else 0
        plaintext = session.decrypt(message_type, message)
        with open(args.session_file, "wb") as f:
            f.write(session.pickle(args.key))
        with open_out(args.plaintext_file) as f:
            f.write(plaintext)

    decrypt.set_defaults(func=do_decrypt)

    args = parser.parse_args()
    args.func(args)


