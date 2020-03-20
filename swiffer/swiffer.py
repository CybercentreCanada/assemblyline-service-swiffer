import hashlib
import os
import re
import ssdeep
from collections import defaultdict

from datetime import datetime, timedelta
from subprocess import Popen, PIPE
from swf.movie import SWF
from swf.consts import ProductKind, ProductEdition

from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic
from assemblyline_v4_service.common.base import ServiceBase

# For now, this is the set we analyze
SWF_TAGS = {
    40: 'NameCharacter',
    41: 'ProductInfo',
    56: 'ExportAssets',
    76: 'SymbolClass',
    82: 'DoABC',
    87: 'DefineBinaryData',
}


# noinspection PyBroadException
class Swiffer(ServiceBase):
    def __init__(self, config=None):
        super(Swiffer, self).__init__(config)
        self.result = None
        self.tag_analyzers = {
            'DoABC': self._do_abc,
            'DefineBinaryData': self._define_binary_data,
            'ExportAssets': self._export_assets,
            'NameCharacter': self._namecharacter,
            'ProductInfo': self._productinfo,
            'SymbolClass': self._symbolclass,
        }
        self.swf = None
        self.tag_summary = None
        self.symbols = None
        self.binary_data = None
        self.exported_assets = None
        self.big_buffers = None
        self.rabcdasm = self.config.get('RABCDASM')
        self.has_product_info = False
        self.anti_decompilation = False
        self.recent_compile = False
        self.disasm_path = None

    def start(self):
        self.log.debug("Service started")
        if not os.path.isfile(self.rabcdasm):
            self.rabcdasm = None

    def get_tool_version(self):
        return "pyswf: 1.5.4 - rabcdasm: 1.18"

    def execute(self, request):
        request.result = Result()
        self.result = request.result
        file_path = request.file_path
        fh = open(file_path, 'rb')
        try:
            self.swf = SWF(fh)
            if self.swf is None:
                raise
        except Exception:
            self.log.exception("Unable to parse file %s:" % request.sha256)
            fh.close()
            raise
        self.tag_summary = defaultdict(list)
        self.symbols = {}
        self.binary_data = {}
        self.exported_assets = []
        self.big_buffers = set()
        self.has_product_info = False
        self.anti_decompilation = False
        self.recent_compile = False
        self.disasm_path = None

        header_subsection = ResultSection(title_text="SWF Header", parent=self.result)
        if self.swf.header.version:
            header_subsection.add_line("Version: %d" % self.swf.header.version)
            header_subsection.add_tag(tag_type="file.swf.header.version", value=str(self.swf.header.version))
        header_subsection.add_line("File length: %d" % self.swf.header.file_length)
        if self.swf.header.frame_size.__str__():
            header_subsection.add_line("Frame size: %s" % self.swf.header.frame_size.__str__())
            header_subsection.add_tag(tag_type="file.swf.header.frame.size", value=self.swf.header.frame_size.__str__())
        if self.swf.header.frame_rate:
            header_subsection.add_line("Frame rate: %d" % self.swf.header.frame_rate)
            header_subsection.add_tag(tag_type="file.swf.header.frame.rate", value=str(self.swf.header.frame_rate))
        if self.swf.header.frame_count:
            header_subsection.add_line("Frame count: %d" % self.swf.header.frame_count)
            header_subsection.add_tag(tag_type="file.swf.header.frame.count", value=str(self.swf.header.frame_count))

        # Parse Tags
        tag_subsection = ResultSection(title_text="SWF Tags", parent=self.result)
        tag_types = []
        for tag in self.swf.tags:
            self.tag_analyzers.get(SWF_TAGS.get(tag.type), self._dummy)(tag)
            tag_types.append(str(tag.type))
        tag_list = ','.join(tag_types)
        tags_ssdeep = ssdeep.hash(tag_list)
        tag_subsection.add_tag(tag_type="file.swf.tags_ssdeep", value=tags_ssdeep)
        # TODO: not sure we want to split those...
        # _, hash_one, hash_two = tags_ssdeep.split(':')
        # tag_subsection.add_tag(tag_type=TAG_TYPE.SWF_TAGS_SSDEEP, value=hash_one)
        # tag_subsection.add_tag(tag_type=TAG_TYPE.SWF_TAGS_SSDEEP, value=hash_two)

        # Script Overview
        if len(self.symbols.keys()) > 0:
            root_symbol = 'unspecified'
            if 0 in self.symbols:
                root_symbol = self.symbols[0]
                self.symbols.pop(0)
            symbol_subsection = ResultSection(title_text="Symbol Summary", parent=self.result)
            symbol_subsection.add_line(f'Main: {root_symbol}')
            if len(self.symbols.keys()) > 0:
                for tag_id, name in sorted([(k, v) for k, v in self.symbols.items()]):
                    symbol_subsection.add_line(f'ID:{tag_id} - {name}')

        if len(self.binary_data.keys()) > 0:
            binary_subsection = ResultSection(title_text="Attached Binary Data", heuristic=Heuristic(3),
                                              parent=self.result)
            for tag_id, tag_data in self.binary_data.items():
                tag_name = self.symbols.get(tag_id, 'unspecified')
                binary_subsection.add_line(f'ID:{tag_id} - {tag_name}')
                try:
                    binary_filename = hashlib.sha256(tag_data).hexdigest() + '.attached_binary'
                    binary_path = os.path.join(self.working_directory, binary_filename)
                    with open(binary_path, 'wb') as fh:
                        fh.write(tag_data)
                    request.add_extracted(binary_path, f"{tag_name}_{tag_id}",
                                          f"SWF Embedded Binary Data {str(tag_id)}")
                except Exception:
                    self.log.exception("Error submitting embedded binary data for swf:")

        tags_subsection = ResultSection(title_text="Tags of Interest")
        for tag in sorted(self.tag_summary.keys()):
            body = []
            summaries = self.tag_summary[tag]
            for summary in summaries:
                summary_line = '\t'.join(summary)
                body.append(summary_line)
            if body:
                subtag_section = ResultSection(title_text=tag, parent=tags_subsection)
                subtag_section.add_lines(body)
        if len(tags_subsection.subsections) > 0:
            self.result.add_section(tags_subsection)

        if len(self.big_buffers) > 0:
            bbs = ResultSection(title_text="Large String Buffers", heuristic=Heuristic(1), parent=self.result)
            for buf in self.big_buffers:
                bbs.add_line("Found a %d byte string." % len(buf))
                buf_filename = ""
                try:
                    buf_filename = hashlib.sha256(buf).hexdigest() + '.stringbuf'
                    buf_path = os.path.join(self.working_directory, buf_filename)
                    with open(buf_path, 'wb') as fh:
                        fh.write(buf)
                    request.add_extracted(buf_path, "AVM2 Large String Buffer.", buf_filename)
                except Exception:
                    self.log.exception("Error submitting AVM2 String Buffer %s" % buf_filename)

        if not self.has_product_info:
            self.log.debug("Missing product info.")
            no_info = ResultSection(title_text="Missing Product Information", heuristic=Heuristic(5),
                                    parent=self.result)
            no_info.add_line("This SWF doesn't specify information about the product that created it.")

        if self.anti_decompilation:
            self.log.debug("Anti-disassembly techniques may be present.")
            no_dis = ResultSection(title_text="Incomplete Disassembly", heuristic=Heuristic(4), parent=self.result)
            no_dis.add_line("This SWF may contain intentional corruption or obfuscation to prevent disassembly.")

        if self.recent_compile:
            recent_compile = ResultSection(title_text="Recent Compilation", heuristic=Heuristic(2), parent=self.result)
            recent_compile.add_line("This SWF was compiled within the last 24 hours.")

        fh.close()

    def analyze_asasm(self, asm):
        # Check for large string buffers
        big_buff_re = r'([A-Za-z0-9+/=]{512,})[^A-Za-z0-9+/=]'
        for buf in re.finditer(big_buff_re, asm):
            self.big_buffers.add(buf.group(1))

        # Check for incomplete decompilation (obfuscation or intentional corruption)
        hexbytes = re.findall(r';\s+0x[A-F0-9]{2}', asm)
        if len(hexbytes) > 10:
            self.anti_decompilation = True

    def analyze_abc(self, a_bytes):
        # Drop the file and disassemble
        abc_path = ""
        try:
            abc_hash = hashlib.sha256(a_bytes).hexdigest()
            abc_filename = abc_hash + '.abc'
            abc_path = os.path.join(self.working_directory, abc_filename)
            disasm_path = os.path.join(self.working_directory, abc_hash)
            with open(abc_path, 'w') as fh:
                fh.write(a_bytes)
            rabcdasm = Popen([self.rabcdasm, abc_path], stdout=PIPE, stderr=PIPE)
            stdout, _ = rabcdasm.communicate()
            # rabcdasm makes a directory from the filename.
            if os.path.isdir(disasm_path):
                for root, dirs, file_names in os.walk(disasm_path):
                    for file_name in file_names:
                        asasm_path = os.path.join(root, file_name)
                        with open(asasm_path, 'r') as fh:
                            self.analyze_asasm(fh.read())
                self.disasm_path = disasm_path
        except Exception:
            self.log.exception("Error disassembling abc file %s:" % abc_path)

    def _do_abc(self, tag):
        self.tag_summary['DoABC'].append(("Name: %s" % tag.abcName, "Length: %d" % len(tag.bytes)))
        if self.rabcdasm:
            self.analyze_abc(tag.bytes)

    def _define_binary_data(self, tag):
        self.binary_data[tag.characterId] = tag.data

    def _export_assets(self, tag):
        if not hasattr(tag, 'exports'):
            return
        for export in tag.exports:
            export_tup = ("Character ID: %s" % export.characterId, "Name: %s" % export.characterName)
            if export_tup not in self.exported_assets:
                self.tag_summary['ExportAssets'].append(export_tup)
                self.exported_assets.append(export_tup)

    def _namecharacter(self, tag):
        self.tag_summary['NameCharacter'].append(("Character ID: %s" % tag.characterId,
                                                  "Name: %s" % tag.characterName))

    def _symbolclass(self, tag):
        for symbol in tag.symbols:
            self.symbols[symbol.tagId] = symbol.name

    def _productinfo(self, tag):
        self.has_product_info = True

        if hasattr(tag, 'compileTime'):
            try:
                compile_time = datetime.fromtimestamp(tag.compileTime / 1000)
                compile_time_str = compile_time.ctime()
                # Flag recent compile time:
                if (datetime.now() - compile_time) < timedelta(hours=24):
                    self.recent_compile = True
            except:
                compile_time_str = "Invalid Compile Time: %s" % repr(tag.compileTime)
        else:
            compile_time_str = 'Missing'

        self.tag_summary['ProductInfo'].append(
            ("Product: %s" % ProductKind.tostring(tag.product),
             "Edition: %s" % ProductEdition.tostring(tag.edition),
             "Version (Major.Minor.Build): %d.%d.%d" % (tag.majorVersion, tag.minorVersion, tag.build),
             "Compile Time: %s" % compile_time_str)
        )

    def _dummy(self, tag):
        pass
