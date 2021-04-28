import os
import os.path

from saw_client import cryptol_load_file, llvm_assume, llvm_verify
from saw_client.llvm import Contract, alias_ty, array, array_ty, cryptol, elem, field, global_var, i8, i32, i64, null, ptr_ty, struct, void
from saw_client.proofscript import ProofScript, z3

from buffer_helpers import *
from curve import *
from load import *
from saw_helpers import *


cryptol_load_file("cryptol/HMAC.cry")

signal_context_ty = alias_ty("struct.signal_context")

message_version = 3

HMAC_CONTEXT_LENGTH = 1
RATCHET_MAC_KEY_LENGTH = 32
SERIALIZED_LENGTH = 42
SIGNAL_MESSAGE_MAC_LENGTH = 8

dummy_signal_crypto_provider = struct( global_var("dummy_random_func")
                                     , global_var("dummy_hmac_sha256_init_func")
                                     , global_var("dummy_hmac_sha256_update_func")
                                     , global_var("dummy_hmac_sha256_final_func")
                                     , global_var("dummy_hmac_sha256_cleanup_func")
                                     , global_var("dummy_sha512_digest_init_func")
                                     , global_var("dummy_sha512_digest_update_func")
                                     , global_var("dummy_sha512_digest_final_func")
                                     , global_var("dummy_sha512_digest_cleanup_func")
                                     , global_var("dummy_encrypt_func")
                                     , global_var("dummy_decrypt_func")
                                     , null()
                                     )

class SignalHmacSha256InitSpec(Contract):
    key_len: int

    def __init__(self, key_len: int):
        super().__init__()
        self.key_len = key_len

    def specification(self) -> None:
        context          = self.alloc(signal_context_ty, read_only=True)
        hmac_context_ptr = self.alloc(ptr_ty(array_ty(HMAC_CONTEXT_LENGTH, i8)))
        (key_data, key)  = ptr_to_fresh(self, array_ty(self.key_len, i8), "key_data")
        self.points_to(context["crypto_provider"], dummy_signal_crypto_provider)

        self.execute_func(context, hmac_context_ptr, key, int_to_64_cryptol(self.key_len))

        # dummy_hmac_context = self.alloc(array_ty(HMAC_CONTEXT_LENGTH, i8),
        #                                 points_to = array(int_to_8_cryptol(42)))
        # self.points_to(hmac_context_ptr, dummy_hmac_context)
        dummy_hmac_context = self.alloc(array_ty(HMAC_CONTEXT_LENGTH, i8),
                                        points_to = cryptol(f"hmac_init`{{ {self.key_len} }} {key_data.name()}"))
        self.points_to(hmac_context_ptr, dummy_hmac_context)
        self.returns(int_to_32_cryptol(0))

class SignalHmacSha256UpdateSpec(Contract):
    data_len: int

    def __init__(self, data_len: int):
        super().__init__()
        self.data_len = data_len

    def specification(self) -> None:
        context                           = self.alloc(signal_context_ty, read_only=True)
        (hmac_context_data, hmac_context) = ptr_to_fresh(self, array_ty(HMAC_CONTEXT_LENGTH, i8), "hmac_context_data")
        (data_data, data)                 = ptr_to_fresh(self, array_ty(self.data_len, i8), "data_data")
        self.points_to(context["crypto_provider"], dummy_signal_crypto_provider)

        self.execute_func(context, hmac_context, data, int_to_64_cryptol(self.data_len))

        # self.points_to(hmac_context, hmac_context_data)
        self.points_to(hmac_context,
                       cryptol(f"hmac_update`{{ {self.data_len} }} {data_data.name()} {hmac_context_data.name()}"))
        self.returns(int_to_32_cryptol(0))

class SignalHmacSha256FinalSpec(Contract):
    def specification(self) -> None:
        context                           = self.alloc(signal_context_ty, read_only=True)
        (hmac_context_data, hmac_context) = ptr_to_fresh(self, array_ty(HMAC_CONTEXT_LENGTH, i8), "hmac_context_data")
        output                            = self.alloc(ptr_ty(buffer_type(SIGNAL_MESSAGE_MAC_LENGTH)))
        self.points_to(context["crypto_provider"], dummy_signal_crypto_provider)

        self.execute_func(context, hmac_context, output)

        # output_buffer = alloc_buffer_aligned(self, SIGNAL_MESSAGE_MAC_LENGTH)
        # self.points_to(output_buffer[0], int_to_64_cryptol(SIGNAL_MESSAGE_MAC_LENGTH), check_target_type = i64)
        output_buffer = alloc_pointsto_buffer(self, SIGNAL_MESSAGE_MAC_LENGTH,
                                              cryptol(f"hmac_final {hmac_context_data.name()}"))

        self.points_to(output, output_buffer)
        self.returns(int_to_32_cryptol(0))

class SignalHmacSha256CleanupSpec(Contract):
    def specification(self) -> None:
        context      = self.alloc(signal_context_ty, read_only=True)
        hmac_context = self.alloc(i8)
        self.points_to(context["crypto_provider"], dummy_signal_crypto_provider)

        self.execute_func(context, hmac_context)

        self.returns(void)

def mk_hmac(serialized_len: int, serialized_data: FreshVar, receiver_identity_key_data : FreshVar,
            sender_identity_key_data: FreshVar, mac_key_len: int, mac_key_data: FreshVar) -> SetupVal:
    sender_identity_buf   = f"[{DJB_TYPE}] # {sender_identity_key_data.name()}   : [{DJB_KEY_LEN} + 1][8]"
    receiver_identity_buf = f"[{DJB_TYPE}] # {receiver_identity_key_data.name()} : [{DJB_KEY_LEN} + 1][8]"
    return cryptol(f""" hmac_final
                         (hmac_update`{{ {serialized_len} }} {serialized_data.name()}
                          (hmac_update`{{ {DJB_KEY_LEN}+1 }} ({receiver_identity_buf})
                           (hmac_update`{{ {DJB_KEY_LEN}+1 }} ({sender_identity_buf})
                            (hmac_init`{{ {mac_key_len} }} {mac_key_data.name()})))) """)

class SignalMessageGetMacSpec(Contract):
    mac_key_len: int
    serialized_len: int

    def __init__(self, mac_key_len: int, serialized_len: int):
        super().__init__()
        self.mac_key_len = mac_key_len
        self.serialized_len = serialized_len

    def specification(self) -> None:
        ec_public_key = alias_ty("struct.ec_public_key")
        buffer_                                                = self.alloc(ptr_ty(buffer_type(SIGNAL_MESSAGE_MAC_LENGTH)))
        (_, sender_identity_key_data, sender_identity_key)     = alloc_ec_public_key(self)
        (_, receiver_identity_key_data, receiver_identity_key) = alloc_ec_public_key(self)
        (mac_key_data, mac_key)                                = ptr_to_fresh(self, array_ty(self.mac_key_len, i8), "mac_key_data")
        (serialized_data, serialized)                          = ptr_to_fresh(self, array_ty(self.serialized_len, i8), "serialized_data")
        global_context                                         = self.alloc(signal_context_ty, read_only=True)
        self.points_to(global_context["crypto_provider"], dummy_signal_crypto_provider)

        self.execute_func(buffer_,
                          int_to_8_cryptol(message_version),
                          sender_identity_key,
                          receiver_identity_key,
                          mac_key, int_to_64_cryptol(self.mac_key_len),
                          serialized, int_to_64_cryptol(self.serialized_len),
                          global_context)

        expected = mk_hmac(self.serialized_len, serialized_data, receiver_identity_key_data,
                           sender_identity_key_data, self.mac_key_len, mac_key_data)

        # buffer_buf = alloc_buffer_aligned(self, SIGNAL_MESSAGE_MAC_LENGTH)
        # self.points_to(buffer_buf[0], int_to_64_cryptol(SIGNAL_MESSAGE_MAC_LENGTH), check_target_type = i64)
        buffer_buf = alloc_pointsto_buffer(self, SIGNAL_MESSAGE_MAC_LENGTH, expected)
        self.points_to(buffer_, buffer_buf)
        self.returns(int_to_32_cryptol(0))

class SignalMessageVerifyMacSpec(Contract):
    mac_key_len: int
    serialized_len: int

    def __init__(self, mac_key_len: int, serialized_len: int):
        super().__init__()
        self.mac_key_len = mac_key_len
        self.serialized_len = serialized_len

    def specification(self) -> None:
        message                                                = self.alloc(alias_ty("struct.signal_message"))
        (_, sender_identity_key_data, sender_identity_key)     = alloc_ec_public_key(self)
        (_, receiver_identity_key_data, receiver_identity_key) = alloc_ec_public_key(self)
        (mac_key_data, mac_key)                                = ptr_to_fresh(self, array_ty(self.mac_key_len, i8), "mac_key_data")
        global_context_unused_as_far_as_i_can_tell             = self.alloc(signal_context_ty, read_only=True)

        base           = self.fresh_var(alias_ty("struct.signal_type_base"), "base")
        message_type   = self.fresh_var(i32, "message_type")
        global_context = self.alloc(signal_context_ty, read_only=True)
        self.points_to(global_context["crypto_provider"], dummy_signal_crypto_provider)

        serialized_message_len  = self.serialized_len - SIGNAL_MESSAGE_MAC_LENGTH
        serialized_message_data = self.fresh_var(array_ty(serialized_message_len, i8), "serialized_message_data")

        expected_mac_data = mk_hmac(serialized_message_len, serialized_message_data, receiver_identity_key_data,
                                    sender_identity_key_data, self.mac_key_len, mac_key_data)

        serialized = alloc_buffer_aligned(self, self.serialized_len)
        self.points_to(serialized[0],                          int_to_64_cryptol(self.serialized_len), check_target_type = None)
        self.points_to(serialized[8],                          serialized_message_data,                check_target_type = None)
        self.points_to(serialized[8 + serialized_message_len], expected_mac_data,                      check_target_type = None)

        base_message = struct(base, message_type, global_context, serialized)
        self.points_to(message["base_message"],    base_message)
        self.points_to(message["message_version"], int_to_8_cryptol(message_version))

        self.execute_func(message,
                          sender_identity_key,
                          receiver_identity_key,
                          mac_key, int_to_64_cryptol(self.mac_key_len),
                          global_context_unused_as_far_as_i_can_tell)

        self.returns(int_to_32_cryptol(1))

uninterps = ["hmac_init", "hmac_update", "hmac_final"]

signal_hmac_sha256_init_ov              = llvm_assume(mod, "signal_hmac_sha256_init",    SignalHmacSha256InitSpec(RATCHET_MAC_KEY_LENGTH))
signal_hmac_sha256_update_djb_key_ov    = llvm_assume(mod, "signal_hmac_sha256_update",  SignalHmacSha256UpdateSpec(DJB_KEY_LEN+1))
signal_hmac_sha256_update_serialized_ov = llvm_assume(mod, "signal_hmac_sha256_update",  SignalHmacSha256UpdateSpec(SERIALIZED_LENGTH))
signal_hmac_sha256_final_ov             = llvm_assume(mod, "signal_hmac_sha256_final",   SignalHmacSha256FinalSpec())
signal_hmac_sha256_cleanup_ov           = llvm_verify(mod, "signal_hmac_sha256_cleanup", SignalHmacSha256CleanupSpec())
signal_message_get_mac_ov               = llvm_verify(mod, "signal_message_get_mac",     SignalMessageGetMacSpec(RATCHET_MAC_KEY_LENGTH, SERIALIZED_LENGTH),
                                                      lemmas=[ signal_hmac_sha256_init_ov, signal_hmac_sha256_update_djb_key_ov,
                                                               signal_hmac_sha256_update_serialized_ov, signal_hmac_sha256_final_ov ],
                                                      script=ProofScript([z3(uninterps)]))
signal_message_verify_mac_ov            = llvm_verify(mod, "signal_message_verify_mac",  SignalMessageVerifyMacSpec(RATCHET_MAC_KEY_LENGTH, SERIALIZED_LENGTH + SIGNAL_MESSAGE_MAC_LENGTH),
                                                      lemmas=[signal_message_get_mac_ov],
                                                      script=ProofScript([z3(uninterps)]))
