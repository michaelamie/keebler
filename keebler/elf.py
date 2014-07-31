import struct


EI_NIDENT = 16
STT_FILE = 4
E_IDENT_FMT = '4s5B7s'
EHDR_FMT = (False, '2H5I6H', '2HI3QI6H')
SHDR_FMT = (False, '10I', '2I4Q2I2Q')
SYM_FMT = (False, '3I2cH', 'I2cH2Q')
SYM_UNPK_VARS = (False, '(st_name, st_value, st_size, st_info, st_other, st_shndx)',
                        '(st_name, st_info, st_other, st_shndx, st_value, st_size)')


class ElfInvalidFormat(Exception): pass


class ElfData(object):
    def __init__(self, data):
        self.shtab = []
        self.shstrtab = {}
        self.shent_by_shstr = {}
        self.symtab = []
        self.strtab = {}
        self._data = data

        self._unpack_e_ident()
        self._unpack_ehdr()
        self._unpack_shtab()
        self._unpack_shstrtab()
        self._load_shent_by_shstr()
        self._unpack_symtab()
        self._unpack_strtab()


    def sections(self):
        section_names = [
            "%2d: %s" % (self.shtab.index(section), self.shstrtab[section['sh_name']])
            for section in self.shtab
        ]
        return '\n'.join(section_names)


    def defined_only(self):
        defined_symbols = [
            self.strtab[entry['st_name']]
            for entry in self._symtab_with_null_and_file_symbols_stripped()
            if entry['st_shndx'] != 0
        ]
        return self._sorted_symbol_string_from_list(defined_symbols)


    def undefined_only(self):
        undefined_symbols = [
            self.strtab[entry['st_name']]
            for entry in self._symtab_with_null_and_file_symbols_stripped()
            if entry['st_shndx'] == 0
        ]
        return self._sorted_symbol_string_from_list(undefined_symbols)


    def _sorted_symbol_string_from_list(self, symbols=[]):
        return '\n'.join(sorted(symbols, key=lambda s: s.lower().replace('_', '')))


    def _symtab_with_null_and_file_symbols_stripped(self):
        return [
            entry for entry in self.symtab
            if ord(entry['st_info']) != STT_FILE and entry['st_name'] != 0
        ]


    def _unpack_e_ident(self):
        try:
            (self.magic, self.ei_class, self.ei_data,
             self.ei_version, self.ei_osabi, self.ei_abiversion,
             self.ei_pad) = struct.unpack(E_IDENT_FMT, self._data[:EI_NIDENT])
        except:
            raise ELFInvalidFormat("Unable to unpack e_ident")

        if not (self.magic == '\x7fELF' and
                (self.ei_class == 1 or self.ei_class == 2) and
                (self.ei_data == 1 or self.ei_data == 2) and
                (self.ei_version == 1)):
            raise ELFInvalidFormat("Invalid e_ident")


    def _unpack_ehdr(self):
        ehdr_fmt = EHDR_FMT[self.ei_class]
        ehdr_end = EI_NIDENT + struct.calcsize(ehdr_fmt)

        try:
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack(ehdr_fmt, self._data[EI_NIDENT:ehdr_end])
        except:
            raise ELFInvalidFormat("Unable to unpack Ehdr")


    def _unpack_shtab(self):
        shdr_fmt = SHDR_FMT[self.ei_class]

        for i in range(0, self.e_shnum):
            sh_entoff = self.e_shoff + i*self.e_shentsize
            sh_entend = sh_entoff + self.e_shentsize

            try:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign,
                 sh_entsize) = struct.unpack(shdr_fmt, self._data[sh_entoff:sh_entend])
            except:
                raise ELFInvalidFormat("Unable to unpack Shdr")

            self.shtab.append({
                'sh_name':      sh_name,
                'sh_type':      sh_type,
                'sh_flags':     sh_flags,
                'sh_addr':      sh_addr,
                'sh_offset':    sh_offset,
                'sh_size':      sh_size,
                'sh_link':      sh_link,
                'sh_info':      sh_info,
                'sh_addralign': sh_addralign,
                'sh_entsize':   sh_entsize
             })


    def _unpack_shstrtab(self):
        sh_ent = self.shtab[self.e_shstrndx]
        shstrtab_off = sh_ent['sh_offset']
        shstrtab_size = sh_ent['sh_size']
        shstrtab_end = shstrtab_off + shstrtab_size

        try:
            shstr = struct.unpack("%ss" % str(shstrtab_size),
                                          self._data[shstrtab_off:shstrtab_end])[0]
            for entry in self.shtab:
                shstrndx = entry['sh_name']
                end = shstr[shstrndx:].find('\x00')
                string = shstr[shstrndx:][:end]
                self.shstrtab[shstrndx] = string
        except:
            raise ELFInvalidFormat("Unable to unpack shstrtab")


    def _load_shent_by_shstr(self):
        for entry in self.shtab:
            self.shent_by_shstr[self.shstrtab[entry['sh_name']]] = self.shtab.index(entry)


    def _unpack_symtab(self):
        sym_fmt = SYM_FMT[self.ei_class]
        sh_ent = self.shtab[self.shent_by_shstr['.symtab']]
        symtab_num = sh_ent['sh_size'] / sh_ent['sh_entsize']

        vars = SYM_UNPK_VARS[self.ei_class]
        unpack = 'struct.unpack(sym_fmt, self._data[st_entoff:st_entend])'

        for i in range(0, symtab_num):
            st_entoff = sh_ent['sh_offset'] + i*sh_ent['sh_entsize']
            st_entend = st_entoff + sh_ent['sh_entsize']

            try:
                exec "%s = %s" % (vars, unpack)
            except:
                raise ELFInvalidFormat("Unable to unpack Sym")

            self.symtab.append({
                'st_name': st_name,
                'st_value': st_value,
                'st_size': st_size,
                'st_info': st_info,
                'st_other': st_other,
                'st_shndx': st_shndx
            })


    def _unpack_strtab(self):
        sh_ent = self.shtab[self.shent_by_shstr['.strtab']]
        strtab_off = sh_ent['sh_offset']
        strtab_size = sh_ent['sh_size']
        strtab_end = strtab_off + strtab_size

        try:
            ststr = struct.unpack("%ss" % str(strtab_size),
                                  self._data[strtab_off:strtab_end])[0]
            for entry in self.symtab:
                ststrndx = entry['st_name']
                end = ststr[ststrndx:].find('\x00')
                string = ststr[ststrndx:][:end]
                self.strtab[ststrndx] = string
        except:
            raise ELFInvalidFormat("Unable to unpack strtab")
