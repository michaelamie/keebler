#!/usr/bin/env python
import argparse
from keebler.elf import ElfData


def parse_filename():
    ap = argparse.ArgumentParser()
    ap.add_argument('filename', nargs='?',
        default='a.out', help='The ELF binary to examine')
    return ap.parse_args().filename


def open_file(filename):
    with open(filename, 'rb') as file:
        file.seek(0)
        data = file.read()
    return data


if __name__ == '__main__':
    file = open_file(parse_filename())
    elf = ElfData(file)

    print "\n%s:\n\n%s" % (
        'Section Header Symbols',
        elf.sections()
    )
    print "\n\n%s:\n\n%s" % (
        'Defined-only Symbols',
        elf.defined_only()
    )
    print "\n\n%s:\n\n%s\n" % (
        'Undefined-only symbols',
        elf.undefined_only()
    )
