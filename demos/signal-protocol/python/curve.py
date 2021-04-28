from saw_client import llvm_verify
from saw_client.llvm import Contract, FreshVar, alias_ty, array_ty, i8, ptr_ty, struct_ty

from buffer_helpers import *
from load import mod
from saw_helpers import *

DJB_TYPE = 0x05
DJB_KEY_LEN = 32

def alloc_ec_public_key(spec: Contract) -> Tuple[FreshVar, FreshVar, SetupVal]:
    signal_type_base_ty = alias_ty("struct.signal_type_base")
    djb_array_ty = array_ty(DJB_KEY_LEN, i8)
    key_base = spec.fresh_var(signal_type_base_ty, "key_base")
    key_data = spec.fresh_var(djb_array_ty, "key_data")
    key = spec.alloc(struct_ty(signal_type_base_ty, djb_array_ty),
                     points_to = struct(key_base, key_data))
    return (key_base, key_data, key)

class ECPublicKeySerializeSpec(Contract):
    def specification(self) -> None:
        length = DJB_KEY_LEN + 1
        buffer_ = self.alloc(ptr_ty(buffer_type(length)))
        (_, key_data, key) = alloc_ec_public_key(self)

        self.execute_func(buffer_, key)

        buf = alloc_pointsto_buffer(self, length,
                                    cryptol(f"[`({DJB_TYPE})] # {key_data.name()} : [{length}][8]"))
        self.points_to(buffer_, buf)
        self.returns(int_to_32_cryptol(0))

ec_public_key_serialize_ov = llvm_verify(mod, "ec_public_key_serialize", ECPublicKeySerializeSpec())
