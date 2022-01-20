from typing import Any, Callable, List, Optional, Tuple
from saw_client import llvm_verify
from saw_client.llvm import Contract, FreshVar, LLVMType, SetupVal, alias_ty, null, struct
from load import mod
from saw_helpers import ptr_to_fresh

from curve import alloc_ec_public_key

import itertools


def makeArbitraryChain(
    spec: Contract, length: int, ty: LLVMType, nextField: str,
    nodeDataFn: Callable[[Contract, SetupVal], Any]
) -> Tuple[Optional[SetupVal], List[Tuple[SetupVal, Any]]]:
    top_ptr = None
    current = None

    allNodesAndData = []
    for i in range(0, length):
        ptr = spec.alloc(ty)
        if current:
            spec.points_to(current["next"], ptr)

        data = nodeDataFn(spec, ptr)
        allNodesAndData.append((ptr, data))

        current = ptr

        if top_ptr is None:
            top_ptr = ptr

    if current:
        spec.points_to(current["next"], null())

    return (top_ptr, allNodesAndData)


class SessonStateFindReceiverChainSpec(Contract):
    def __init__(self, index: int, count: int):
        super().__init__()
        self.index = index
        self.count = count

    def specification(self) -> None:
        assert self.index >= 0 and self.index < self.count

        # Create an arbitrary chain of nodes
        (top_ptr, allData) = makeArbitraryChain(self, self.count,
                                                alias_ty("struct.session_state_receiver_chain"),
                                                "next", self.node_with_key)

        # What we are going to look for
        expected_node, expected_data = allData[self.index]

        # Uniqueness preconditions
        # TODO: Be unique *only* up to the index we are looking for
        all_keys = [key_data for (_, (_, key_data, _)) in allData]
        for (k1, k2) in itertools.product(all_keys, all_keys):
            if k1 != k2:
                self.precondition(f"{k1.name()} != {k2.name()}")

        assert top_ptr is not None
        assert expected_data is not None
        assert expected_node is not None

        # Session state with the correct chain
        state = self.alloc(alias_ty("struct.session_state"))
        self.points_to(state["receiver_chain_head"], top_ptr)

        # A key pointer for the key we picked
        new_key_ptr = self.ec_specific_public_key_ptr(expected_data[0], expected_data[1])

        # Execute the function
        self.execute_func(state, new_key_ptr)
        # self.execute_func(state, expected_key_ptr)

        # TODO: This is not preferred. In reality, we could accept *any* node as long as it has the
        # right rachet key. But how do we express that?
        self.returns(expected_node)

    def node_with_key(self, _: Contract, ptr: SetupVal) -> Tuple[SetupVal, FreshVar, SetupVal]:
        (random_key_base, random_key_data, random_key_ptr) = alloc_ec_public_key(self)
        self.points_to(ptr["sender_ratchet_key"], random_key_ptr)

        return (random_key_base, random_key_data, random_key_ptr)

    def ec_specific_public_key_ptr(self, key_base, key_data):
        key_ptr = self.alloc(alias_ty("struct.ec_public_key"),
                             points_to=struct(key_base, key_data))
        return key_ptr


class SessonStateGetReceiverChainKeySpec(Contract):
    def __init__(self, index: int, count: int):
        super().__init__()
        self.index = index
        self.count = count

    def specification(self) -> None:
        assert self.index >= 0 and self.index < self.count

        # Create an arbitrary chain of nodes
        (top_ptr, allData) = makeArbitraryChain(self, self.count,
                                                alias_ty("struct.session_state_receiver_chain"),
                                                "next", self.node_with_key)

        # What we are going to look for
        expected_node, expected_data = allData[self.index]
        expected_chain_key_ptr = expected_data[3]

        # Uniqueness preconditions
        # TODO: Be unique *only* up to the index we are looking for
        all_keys = [key_data for (_, (_, key_data, _, _)) in allData]
        for (k1, k2) in itertools.product(all_keys, all_keys):
            if k1 != k2:
                self.precondition(f"{k1.name()} != {k2.name()}")

        assert top_ptr is not None
        assert expected_data is not None
        assert expected_node is not None

        # Session state with the correct chain
        state = self.alloc(alias_ty("struct.session_state"))
        self.points_to(state["receiver_chain_head"], top_ptr)

        # A key pointer for the key we picked
        new_key_ptr = self.ec_specific_public_key_ptr(expected_data[0], expected_data[1])

        # Execute the function
        self.execute_func(state, new_key_ptr)

        # We expect our specific chain key pointer
        self.returns(expected_chain_key_ptr)

    def node_with_key(self, _: Contract, ptr: SetupVal) -> Tuple[FreshVar, FreshVar, SetupVal, SetupVal]:
        (random_key_base, random_key_data, random_key_ptr) = alloc_ec_public_key(self)
        random_chain_key_data, random_chain_key_ptr = ptr_to_fresh(self, alias_ty("struct.ratchet_chain_key"))

        self.points_to(ptr["sender_ratchet_key"], random_key_ptr)
        self.points_to(ptr["chain_key"], random_chain_key_ptr)

        return (random_key_base, random_key_data, random_key_ptr, random_chain_key_ptr)

    def ec_specific_public_key_ptr(self, key_base, key_data):
        key_ptr = self.alloc(alias_ty("struct.ec_public_key"),
                             points_to=struct(key_base, key_data))
        return key_ptr


session_state_find_receiver_chain_ov1 = llvm_verify(mod, "session_state_find_receiver_chain", SessonStateFindReceiverChainSpec(2, 5))
session_state_find_receiver_chain_ov2 = llvm_verify(mod, "session_state_find_receiver_chain", SessonStateFindReceiverChainSpec(4, 5))
session_state_find_receiver_chain_ov3 = llvm_verify(mod, "session_state_find_receiver_chain", SessonStateFindReceiverChainSpec(0, 5))

session_state_get_receiver_chain_key_ov1 = llvm_verify(mod, "session_state_get_receiver_chain_key", SessonStateGetReceiverChainKeySpec(2, 5))
session_state_get_receiver_chain_key_ov2 = llvm_verify(mod, "session_state_get_receiver_chain_key", SessonStateGetReceiverChainKeySpec(4, 5))
session_state_get_receiver_chain_key_ov3 = llvm_verify(mod, "session_state_get_receiver_chain_key", SessonStateGetReceiverChainKeySpec(0, 5))
