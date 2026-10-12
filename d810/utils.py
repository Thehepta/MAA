import ctypes
import logging

import ida_hexrays
from d810.hexrays_formatters import format_mop_t
from d810.hexrays_helpers import MSB_TABLE
from ida_hexrays import mop_t, mop_r, get_mreg_name, mop_S, mop_v, mop_a

CTYPE_SIGNED_TABLE = {1: ctypes.c_int8, 2: ctypes.c_int16, 4: ctypes.c_int32, 8: ctypes.c_int64}
CTYPE_UNSIGNED_TABLE = {1: ctypes.c_uint8, 2: ctypes.c_uint16, 4: ctypes.c_uint32, 8: ctypes.c_uint64}


class UnflatteningException(Exception):
    pass


class DispatcherUnflatteningException(UnflatteningException):
    pass


class NotDuplicableFatherException(UnflatteningException):
    pass


class NotResolvableFatherException(UnflatteningException):
    pass


def get_all_possibles_values(mop_histories, searched_mop_list, verbose=False):
    mop_cst_values_list = []
    for mop_history in mop_histories:
        mop_cst_values_list.append([mop_history.get_mop_constant_value(searched_mop)
                                    for searched_mop in searched_mop_list])
    return mop_cst_values_list


def get_all_subclasses(python_class):
    python_class.__subclasses__()

    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)


def unsigned_to_signed(unsigned_value, nb_bytes):
    return CTYPE_SIGNED_TABLE[nb_bytes](unsigned_value).value


def signed_to_unsigned(signed_value, nb_bytes):
    return CTYPE_UNSIGNED_TABLE[nb_bytes](signed_value).value


def get_msb(value, nb_bytes):
    return (value & MSB_TABLE[nb_bytes]) >> (nb_bytes * 8 - 1)


def get_add_cf(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))), nb_bytes)


def get_add_of(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb(((op1 ^ res) & (~(op1 ^ op2))), nb_bytes)


def get_sub_cf(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))), nb_bytes)


def get_sub_of(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb(((op1 ^ res) & (op1 ^ op2)), nb_bytes)


def get_parity_flag(op1, op2, nb_bytes):
    tmp = CTYPE_UNSIGNED_TABLE[nb_bytes](op1 - op2).value
    return (bin(tmp).count("1") + 1) % 2


def ror(x, n, nb_bits=32):
    mask = (2 ** n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (nb_bits - n))


def rol(x, n, nb_bits=32):
    return ror(x, nb_bits - n, nb_bits)


def get_mop_name(mop: mop_t) -> str:
    """
    Generate a unique identifier string for a mop.
    Uses structural properties (type + internal id) rather than display string.
    Does NOT include size — consistent with equal_mops_ignore_size which treats
    the same register/stack slot as identical regardless of access size.
    Size handling is done at the expression level (via slice/extend).
    """
    if mop.t == mop_r:
        width = mop.size
        name = get_mreg_name(mop.r, width)
        return name
    elif mop.t == mop_S:
        # Stack variable: use stack offset
        # return mop.dstr()
        return "Stvar_{:x}".format(mop.s.off)
    elif mop.t == mop_v:
        # Global variable: use address
        return "Gvar_{:x}".format(mop.g)
    elif mop.t == mop_a:
        return get_mop_name(mop.a)
    else:
        # Fallback: use display string
        return format_mop_t(mop)


def find_all_paths_dfs(start_block, end_blocks):
    if not start_block or not end_blocks:
        return []

    end_block_nums = set(blk.serial for blk in end_blocks)
    # print(f"终点块编号: {end_block_nums}")  # 调试输出

    all_paths = []
    visited = set()

    def dfs(current_block, path):
        current_num = current_block.serial

        if current_num in visited:
            return

        if current_num in end_block_nums:
            tmp_path = path.copy()
            tmp_path.append(current_num)
            # print(f"到达终点 {current_num}, 路径: {tmp_path}")  # 调试输出
            all_paths.append(tmp_path)
            return

        path.append(current_num)
        visited.add(current_num)

        for succ_block in current_block.succs():
            dfs(succ_block, path)

        path.pop()
        visited.remove(current_num)

    dfs(start_block, [])
    unique_paths = []
    seen = set()
    for path in all_paths:
        path_tuple = tuple(path)
        if path_tuple not in seen:
            seen.add(path_tuple)
            unique_paths.append(path)
    return unique_paths


# 输出控制台
def enable_console_log(logger):
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler()
        logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

def disable_console_log(logger):
    """
    动态关闭 console log（不重启 IDA）
    """
    for h in list(logger.handlers):
        if isinstance(h, logging.StreamHandler):
            logger.removeHandler(h)
            h.close()
    logger.propagate = True   # 可选：让父 logger 接管


# 输出文件
def enable_file_log(logger, file_path):
    if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        handler = logging.FileHandler(file_path, encoding="utf-8")
        logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)


def create_console_logger(name="my_logger", level=logging.DEBUG):
    """快速创建一个控制台日志器"""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 避免重复添加 handler
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False

    return logger
