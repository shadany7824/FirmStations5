"""Maps an ElfImage into an emulated address space.

`mem` is anything with map(addr, size, perms) and write(addr, data).
Permissions use the same bits as Unicorn: R=1, W=2, X=4.
"""
from .elf import PF_R, PF_W, PF_X

PAGE = 0x1000
PERM_R, PERM_W, PERM_X = 1, 2, 4


def align_down(x):
    return x & ~(PAGE - 1)


def align_up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)


def elf_flags_to_perms(flags):
    perms = 0
    if flags & PF_R:
        perms |= PERM_R
    if flags & PF_W:
        perms |= PERM_W
    if flags & PF_X:
        perms |= PERM_X
    return perms


def load_image(image, data, mem):
    """Map all segments, copy file bytes in, return the entry point."""
    # Segments can share a page, so work out permissions per page first.
    page_perms = {}
    for seg in image.segments:
        perms = elf_flags_to_perms(seg.flags)
        for page in range(align_down(seg.vaddr), align_up(seg.vaddr + seg.memsz), PAGE):
            page_perms[page] = page_perms.get(page, 0) | perms

    # Merge neighbouring pages with equal permissions into single mappings.
    run_start = run_perms = prev = None
    for page in sorted(page_perms):
        perms = page_perms[page]
        if run_start is not None and page == prev + PAGE and perms == run_perms:
            prev = page
            continue
        if run_start is not None:
            mem.map(run_start, prev + PAGE - run_start, run_perms)
        run_start, run_perms, prev = page, perms, page
    if run_start is not None:
        mem.map(run_start, prev + PAGE - run_start, run_perms)

    # Fresh mappings are zero-filled, so the .bss tail (memsz > filesz) needs no work.
    for seg in image.segments:
        if seg.filesz:
            mem.write(seg.vaddr, data[seg.offset:seg.offset + seg.filesz])

    return image.entry
