import os
import os.path

from saw_client import LogResults, connect, llvm_load_module, view

dir_path = os.path.dirname(os.path.realpath(__file__))

connect()
view(LogResults())

path = [os.path.dirname(dir_path), "c", "libsignal-everything.bc"]
bcname = os.path.join(*path)
print(bcname)
mod = llvm_load_module(bcname)
