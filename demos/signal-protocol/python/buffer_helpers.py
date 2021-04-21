from saw_client.llvm import Contract, LLVMType, SetupVal, array_ty, cryptol, i8, struct

def int_to_8_cryptol(length: int):
    return cryptol("`{i}:[8]".format(i=length))

def int_to_32_cryptol(length: int):
    return cryptol("`{i}:[32]".format(i=length))

def int_to_64_cryptol(length: int):
    return cryptol("`{i}:[64]".format(i=length))

def buffer_type(length: int) -> LLVMType:
    return array_ty(8 + length, i8)

def alloc_buffer_aligned(spec: Contract, length: int) -> SetupVal:
    return spec.alloc(buffer_type(length), alignment = 16)

def alloc_buffer_aligned_readonly(spec: Contract, length: int) -> SetupVal:
    return spec.alloc(buffer_type(length), alignment = 16, read_only = True)

def alloc_pointsto_buffer(spec: Contract, length: int, data: SetupVal) -> SetupVal:
    buf = alloc_buffer_aligned(spec, length)
    spec.points_to(buf, struct(int_to_64_cryptol(length), data), check_target_type = None)
    return buf

def alloc_pointsto_buffer_readonly(spec: Contract, length: int, data: SetupVal) -> SetupVal:
    buf = alloc_buffer_aligned_readonly(spec, length)
    spec.points_to(buf, struct(int_to_64_cryptol(length), data), check_target_type = None)
    return buf
