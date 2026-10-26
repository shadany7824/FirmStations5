"""Turning NIDs back into names, for readable messages.

A NID is a one-way hash, so we can only recognise NIDs of names we already know: we hash every
name below (plus every function orbemu implements) and compare. COMMON_NAMES are the imports of a
real OpenOrbis hello-world build plus other well-known PlayStation and POSIX functions.
"""
from .nid import nid_for, split_import_name

COMMON_NAMES = """
sysconf open ioctl sigprocmask fstat nanosleep _write sigaction _exit pthread_cond_broadcast
pthread_rwlock_wrlock pthread_cond_destroy pthread_rwlock_rdlock pthread_setspecific pthread_equal
pthread_mutex_unlock pthread_cond_timedwait poll pthread_rwlock_unlock pthread_detach
pthread_mutexattr_init pthread_mutex_lock munmap pthread_mutex_destroy pthread_mutex_trylock mmap
sched_yield pthread_join pthread_getspecific pthread_mutexattr_destroy pthread_self close
pthread_mutexattr_settype pthread_key_create pthread_mutex_init madvise _writev lseek __error
pthread_once pthread_cond_wait raise pthread_cond_signal sceKernelUsleep
printf puts putchar malloc free calloc realloc memcpy memset memmove strlen strcmp strcpy
sceKernelSleep sceKernelGetProcessTime sceKernelGetProcessTimeCounter
sceKernelGetProcessTimeCounterFrequency sceKernelDebugOutText
scePadInit scePadOpen scePadClose scePadRead scePadReadState scePadSetVibration scePadSetLightBar
scePadResetLightBar scePadGetHandle scePadGetControllerInformation
sceUserServiceInitialize sceUserServiceTerminate sceUserServiceGetInitialUser
sceVideoOutOpen sceVideoOutClose sceVideoOutRegisterBuffers sceVideoOutSubmitFlip
sceVideoOutSetFlipRate sceVideoOutSetBufferAttribute sceVideoOutGetResolutionStatus
sceSystemServiceHideSplashScreen sceSysmoduleLoadModule
""".split()

_map = None


def _name_map(registry=None):
    global _map
    if _map is None:
        _map = {nid_for(n): n for n in COMMON_NAMES}
    if registry is None:
        return _map
    merged = dict(_map)
    for n in list(registry.functions) + list(registry.native):
        merged[nid_for(n)] = n
    return merged


def name_for(symbol, registry=None):
    """The plain name behind an import symbol ('7H0iTOciTLo#B#B' -> 'pthread_mutex_lock'), or None."""
    if "#" not in symbol:
        return symbol
    return _name_map(registry).get(split_import_name(symbol)[0])


def pretty(symbol, registry=None):
    """'pthread_mutex_lock [7H0iTOciTLo]' when the name is known, else the symbol itself."""
    name = name_for(symbol, registry)
    if name is None or name == symbol:
        return symbol
    return f"{name} [{split_import_name(symbol)[0]}]"
