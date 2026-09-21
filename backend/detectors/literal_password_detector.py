"""Detect literal password material without assuming passwords are random."""
import base64
import re
from .candidate import DetectionCandidate
from .entropy_detector import EntropyDetector
from .finding import Severity

class LiteralPasswordDetector:
    _ASSIGNMENT = re.compile(EntropyDetector._ASSIGNMENT.pattern.replace('[:=]', '(?:=>|[:=])'))
    _XML = re.compile(EntropyDetector._XML.pattern.replace('{8,2048}', '{1,2048}'))
    _SETTER = re.compile(EntropyDetector._SETTER.pattern.replace('{8,2048}', '{1,2048}'))
    _URL = re.compile(EntropyDetector._URL.pattern.replace('{8,2048}', '{1,2048}'))
    _COMMAND = re.compile(EntropyDetector._COMMAND.pattern.replace('{8,256}', '{1,256}'))
    _PS_LITERAL = re.compile(EntropyDetector._PS_LITERAL.pattern.replace('{8,256}', '{1,256}'), re.I)
    _SQL = re.compile(r'''(?i)\b(?:IDENTIFIED[ \t]+BY|WITH[ \t]+PASSWORD)[ \t]+['"](?P<value>[^'"\r\n]{1,2048})['"]''')
    _INDEXED = re.compile(r'''(?i)\[["'](?:password|passwd|pwd)["']\][ \t]*=(?!=)[ \t]*['"](?P<value>[^'"\r\n]{1,2048})['"]''')

    _REFERENCE = re.compile(r'\$\{|\$\(|\{\{|\{%|%\([A-Za-z_]|%[A-Z_]+%|\$[A-Za-z_]|#\{|%[-+0-9.]*[sdfr]|^<[^>]+>$')
    _TEMPLATE = re.compile(r'(?i)^(?:your[-_ ]|replace[-_ ]|placeholder|changeme|example(?:[-_ ]|[0-9])|enter[-_ ])')

    @classmethod
    def literal(cls,value):
        return (bool(value.strip()) and len(value)<=2048 and not cls._REFERENCE.search(value)
                and not cls._TEMPLATE.search(value) and not value.startswith(EntropyDetector._REFERENCES)
                and not re.fullmatch(r'\*{2,}',value)
                and value.casefold() not in {'null','none','undefined','true','false','...','*****','********','-','|','>'})

    def detect(self,text_file):
        return tuple(c.to_finding() for c in self.detect_candidates(text_file))

    def detect_candidates(self,text_file):
        text=text_file.text
        path=text_file.metadata.relative_path
        basename=path.replace('\\','/').rsplit('/',1)[-1].lower()
        config=path.lower().endswith(EntropyDetector._CONFIG_SUFFIXES) or basename.startswith('.env.')
        result=[]
        def add(value,position):
            line=text.count('\n',0,position)+1
            result.append(DetectionCandidate(detector='contextual',rule_id='hardcoded_password',category='password',
                severity=Severity.MEDIUM,file_path=path,line_start=line,line_end=line,matched_value=value))
        for match in self._ASSIGNMENT.finditer(text):
            words=re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',match.group('name')).lower()
            if re.split(r'[^a-z0-9]+',words)[-1] not in {'password','passwd','pwd'}:
                continue
            group=next(k for k in ('double','single','bare') if match.group(k) is not None)
            value=match.group(group)
            if group=='bare' and (not config or text[match.end():].startswith(('{', '}'))):
                continue
            # Reject expression continuations and comparison operands.
            tail=text[match.end():].lstrip(' \t')
            if tail.startswith(('(','.','+','[','==','!=')):
                continue
            if self.literal(value):add(value,match.start(group))
        for match in EntropyDetector._AUTH_HEADER.finditer(text):
            if match.group('scheme').casefold()!='basic':continue
            try:
                decoded=base64.b64decode(match.group('value'),validate=True).decode('utf8')
            except (ValueError,UnicodeError):continue
            user,separator,password=decoded.partition(':')
            if separator and user and self.literal(password):add(match.group('value'),match.start('value'))
        for pattern in (self._XML,self._SETTER,self._URL,self._SQL,self._INDEXED,self._COMMAND):
            for match in pattern.finditer(text):
                name=match.groupdict().get('name','password').casefold()
                if name not in {'password','passwd','pwd'}:continue
                if pattern is self._COMMAND:
                    prefix=text[match.start():match.start('value')]
                    if '--password' not in prefix.casefold() and not prefix.rstrip("\"'").endswith(':'):continue
                value=match.group('value')
                if self.literal(value):add(value,match.start('value'))
        for match in EntropyDetector._POWERSHELL.finditer(text):
            args = match.group('args')
            literal = self._PS_LITERAL.search(args)
            if literal is not None and re.search(r'(?i)(?:^|\s)-AsPlainText(?:\s|$)', args):
                value = literal.group('value')
                if self.literal(value):
                    add(value, match.start('args') + literal.start('value'))
        return tuple(result)
