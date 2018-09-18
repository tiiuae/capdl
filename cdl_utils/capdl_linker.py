#!/usr/bin/env python
#
# Copyright 201*, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#

import sys
import argparse
import pickle
import logging
import os
import sh
import tempfile
import pkg_resources
import six
pkg_resources.require("jinja2>=2.10")
from jinja2 import Environment, BaseLoader, FileSystemLoader

from capdl import seL4_CapTableObject, ObjectAllocator, CSpaceAllocator, \
            ELF, lookup_architecture, Cap, seL4_FrameObject, CNode, Spec

CSPACE_TEMPLATE_FILE = os.path.join(os.path.dirname(__file__), "templates/cspace.template.c")


def manifest(CSPACE_LAYOUT, SPECIAL_PAGES, architecture, targets):

    temp_file = open(CSPACE_TEMPLATE_FILE, 'r').read()
    template = Environment(loader=BaseLoader).from_string(temp_file)


    c_allocs = {}
    for (e, ccspace) in targets:
        name = os.path.basename(e)
        c_allocs[name] = []

        cnode = CNode("cnode_%s" % name)
        c_alloc = CSpaceAllocator(cnode)
        slots = []
        symbols = SPECIAL_PAGES[name]

        for (symbol, obj, kwargs) in CSPACE_LAYOUT[name]:            
            slot = c_alloc.alloc(None, **kwargs)
            slots.append((symbol,slot))

        cnode.finalise_size(arch=lookup_architecture(architecture))
        metadata = zip(CSPACE_LAYOUT[name], slots)
        c_allocs[name] = (c_alloc, metadata)
        if ccspace:
            data = template.render({'slots': slots, 'symbols': symbols, 'progname': name, 'ipc_buffer_symbol': "mainIpcBuffer"})
            ccspace.write(data)
    return c_allocs

def infer_kwargs(object, arch, kwargs):
    if isinstance(object, CNode):
        kwargs['guard_size'] = arch.word_size_bits() - object.size_bits
    return kwargs

def final_spec(c_allocs, OBJECTS, elf_files, architecture):
    elfs = {}
    arch = lookup_architecture(architecture)
    obj_space = ObjectAllocator()
    obj_space.spec.arch = architecture
    spec = Spec(architecture)
    [spec.add_object(c_alloc.cnode) for (c_alloc, metadata) in c_allocs.values()]
    obj_space.merge(spec)

    for k,(v,o) in OBJECTS.iteritems():
        obj_space.alloc(v,name=k, **o)


    for e in [item for sublist in elf_files for item in sublist]:
        try:
            name = os.path.basename(e)
            if name in elfs:
               raise Exception('duplicate ELF files of name \'%s\' encountered' % name)
            elf = ELF(e, name, architecture)
            (c_alloc, metadata) = c_allocs[name]
            cnode=c_alloc.cnode
            cspace = Cap(cnode, guard_size=arch.word_size_bits() - cnode.size_bits)

# Avoid inferring a TCB as we've already created our own.
            (elf_spec, special) = elf.get_spec(infer_asid=False)
            obj_space.merge(elf_spec)

            for ((_, object_ref, kwargs), (_, slot)) in metadata:
                if (isinstance(object_ref, six.string_types)):
                    kwargs = infer_kwargs(obj_space[object_ref], arch, kwargs)
                    cnode[slot] = Cap(obj_space[object_ref], **kwargs)
                elif object_ref is seL4_FrameObject:
                    cnode[slot] = Cap(special[elf.get_symbol_vaddr(kwargs['symbol'])], read=True, write=True, grant=False)


            sp = elf.get_symbol_vaddr("stack")+elf.get_symbol_size("stack");
            ipc_addr = elf.get_symbol_vaddr("mainIpcBuffer");
            progsymbol = elf.get_symbol_vaddr("progname")
            vsyscall = elf.get_symbol_vaddr("sel4_vsyscall")
            init_array = [0,0,0,0,2,progsymbol,1,0,0,32,vsyscall,0,0]
            tcb = obj_space["tcb_%s" % name]
            tcb['cspace'] = cspace

            tcb['ipc_buffer_slot'] = Cap(special[ipc_addr], read=True, write=True, grant=False) # RW

            tcb.addr = ipc_addr
            tcb.init = init_array
            tcb.sp = sp


            elfs[name] = (e, elf)
        except Exception as inst:
            raise
    return obj_space

def main():
    parser = argparse.ArgumentParser(
                description="")
    parser.add_argument('--architecture', '--arch', default='aarch32',
        type=lambda x: type('')(x).lower(), choices=('aarch32', 'arm_hyp', 'ia32', 'x86_64'),
        help='Target architecture.')
    subparsers = parser.add_subparsers()
    parser_a = subparsers.add_parser('build_cnode')
    parser_a.add_argument('--elffile', nargs='+', action='append')
    parser_a.add_argument('--manifest', type=argparse.FileType('r'))
    parser_a.add_argument('--manifest-out', type=argparse.FileType('wb'))
    parser_a.add_argument('--ccspace', nargs='+', type=argparse.FileType('w'), action='append')
    parser_a.set_defaults(which="build_cnode")
    parser_b = subparsers.add_parser('gen_cdl')
    parser_b.add_argument('--outfile', type=argparse.FileType('w'))
    parser_b.add_argument('--manifest-in', nargs='+', action='append', type=argparse.FileType('rb'))
    parser_b.add_argument('--elffile', nargs='+', action='append')
    parser_b.set_defaults(which="gen_cdl")

    parser_c = subparsers.add_parser('depends')
    parser_c.add_argument('--build_cnode', action='store_true')
    parser_c.add_argument('--gen_cdl', action='store_true')
    parser_c.set_defaults(which="depends")

    args = parser.parse_args()

    if args.which is "depends":
        if args.build_cnode:
            print(CSPACE_TEMPLATE_FILE)

    if args.which is "build_cnode":
        (OBJECTS, CSPACE_LAYOUT, SPECIAL_PAGES) = pickle.load(args.manifest)
        elfs = [item for sublist in args.elffile for item in sublist]
        cspaces = [item for sublist in args.ccspace for item in sublist]
        targets = zip(elfs, cspaces)
        c_allocs = manifest(CSPACE_LAYOUT, SPECIAL_PAGES, args.architecture, targets)
        if args.ccspace:
            pickle.dump((c_allocs, OBJECTS), args.manifest_out)
            return 0

    if args.which is "gen_cdl":
        c_allocs = {}
        OBJECTS = {}
        for file in [item for sublist in args.manifest_in for item in sublist]:
            (_c_allocs, _OBJECTS) = pickle.load(file)
            assert _c_allocs.keys() not in c_allocs.keys()
            c_allocs.update(_c_allocs)
            OBJECTS.update(_OBJECTS)



    obj_space = final_spec(c_allocs, OBJECTS, args.elffile, args.architecture)
    args.outfile.write(repr(obj_space.spec))

    return 0

if __name__ == '__main__':
    sys.exit(main())
