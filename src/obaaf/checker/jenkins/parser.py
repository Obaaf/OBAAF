"""A structural parser for Jenkins pipelines, written for analysis rather than execution.

It builds a small syntax tree of calls, closures, strings, lists and maps: enough to see
pipeline sections, stages, steps, credential bindings and what reaches a shell. It covers
the Groovy that Jenkinsfiles use, not all of Groovy. Statements it cannot read become
Opaque nodes with their line, so coverage reports them instead of silently skipping
them. Nothing is compiled or executed (Jenkins design, section 5).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from obaaf.checker.jenkins.lexer import DEADLINE_SECONDS, LexError, LimitExceeded, Tok, tokenize

MAX_DEPTH = 64   # nested blocks, closures and brackets; real Jenkinsfiles stay far below this


class ParseError(ValueError):
    def __init__(self, message: str, tok: Tok):
        super().__init__(f"line {tok.line}: {message}")
        self.line, self.col = tok.line, tok.col


# ---------------------------------------------------------------------------- nodes
@dataclass
class Node:
    line: int = field(default=0, kw_only=True)
    col: int = field(default=0, kw_only=True)


@dataclass
class Name(Node):
    name: str


@dataclass
class Str(Node):
    tok: Tok

    @property
    def interpolated(self) -> bool:
        return self.tok.interpolated

    @property
    def exprs(self) -> list[str]:
        return [text for kind, text in self.tok.parts if kind == "expr"]

    def text(self) -> str:
        return self.tok.literal()


@dataclass
class Num(Node):
    value: str


@dataclass
class ListLit(Node):
    items: list


@dataclass
class MapLit(Node):
    entries: list   # (key, value): key is a str for literal keys, else a Node


@dataclass
class Prop(Node):
    target: Node
    name: str


@dataclass
class Index(Node):
    target: Node
    index: Node


@dataclass
class Call(Node):
    callee: Node
    args: list = field(default_factory=list)      # positional argument nodes
    named: list = field(default_factory=list)     # (name, node)
    closure: "Block | None" = None
    command: bool = False                          # written without parentheses


@dataclass
class Closure(Node):
    params: list
    body: "Block"


@dataclass
class Unary(Node):
    op: str
    operand: Node


@dataclass
class Binary(Node):
    op: str
    left: Node
    right: Node


@dataclass
class Ternary(Node):
    cond: Node
    then: Node
    otherwise: Node


@dataclass
class Opaque(Node):
    reason: str


@dataclass
class Block(Node):
    stmts: list


@dataclass
class ExprStmt(Node):
    expr: Node


@dataclass
class Decl(Node):
    name: str
    value: Node | None


@dataclass
class Assign(Node):
    target: Node
    op: str
    value: Node


@dataclass
class If(Node):
    cond: Node
    then: Block
    otherwise: Block | None


@dataclass
class Loop(Node):
    header: list
    body: Block


@dataclass
class Try(Node):
    body: Block
    handlers: list   # Blocks for catch and finally
    kinds: list = field(default_factory=list)   # "catch" or "finally", one per handler


@dataclass
class Switch(Node):
    subject: Node
    cases: list      # Blocks


@dataclass
class Return(Node):
    value: Node | None
    throw: bool = field(default=False, kw_only=True)   # a throw statement, not a return


@dataclass
class MethodDef(Node):
    name: str
    params: list
    body: Block


@dataclass
class ClassDef(Node):
    name: str
    body: Block


@dataclass
class Import(Node):
    path: str


@dataclass
class Annotated(Node):
    annotation: str
    args: list
    named: list
    target: Node | None


def path_of(node) -> str | None:
    """`env.CHANGE_TITLE` for Name/Prop chains; None for anything else. Iterative: chains can be long."""
    parts = []
    while isinstance(node, Prop):
        parts.append(node.name)
        node = node.target
    if not isinstance(node, Name):
        return None
    parts.append(node.name)
    return ".".join(reversed(parts))


def callee_name(call: Call) -> str | None:
    return path_of(call.callee)


# --------------------------------------------------------------------------- parser
_STATEMENT_KEYWORDS = {"if", "for", "while", "do", "try", "switch", "return", "throw", "break", "continue",
                       "import", "package", "class", "interface", "enum", "trait", "assert"}
_MODIFIERS = {"def", "final", "static", "private", "public", "protected", "synchronized", "abstract",
              "transient", "volatile", "var"}
_PRIMITIVES = {"int", "long", "short", "byte", "char", "boolean", "float", "double", "void"}
_BINARY = {"+", "-", "*", "/", "%", "**", "==", "!=", "===", "!==", "<", ">", "<=", ">=", "<=>", "&&", "||", "&", "|", "^",
           "<<", ">>", ">>>", "=~", "==~", "!=~", "..", "..<", "?:"}
_BINARY_WORDS = {"in", "instanceof", "as"}
# Groovy operator precedence, loosest first (Groovy language specification, "Operator precedence").
_PRECEDENCE = {"?:": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6, "=~": 7, "==~": 7, "!=~": 7,
               "==": 8, "!=": 8, "<=>": 8, "===": 8, "!==": 8,
               "<": 9, "<=": 9, ">": 9, ">=": 9, "in": 9, "!in": 9, "instanceof": 9, "!instanceof": 9, "as": 9,
               "<<": 10, ">>": 10, ">>>": 10, "..": 10, "..<": 10,
               "+": 11, "-": 11, "*": 12, "/": 12, "%": 12, "**": 13}
_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
_NOT_ARG_WORDS = {"in", "instanceof", "as", "else", "catch", "finally"}


class Parser:
    def __init__(self, tokens: list[Tok], deadline: float):
        self.toks = tokens
        self.i = 0
        self.depth = 0
        self.deadline = deadline
        self.problems: list[tuple[int, str]] = []
        self.steps = 0

    # -- token helpers -------------------------------------------------------------
    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def peek(self, n: int = 1) -> Tok:
        j = min(self.i + n, len(self.toks) - 1)
        return self.toks[j]

    def at(self, kind: str, value: str | None = None) -> bool:
        t = self.tok
        return t.kind == kind and (value is None or t.value == value)

    def at_op(self, *values: str) -> bool:
        return self.tok.kind == "op" and self.tok.value in values

    def advance(self) -> Tok:
        t = self.tok
        if t.kind != "eof":
            self.i += 1
        self.steps += 1
        if self.steps % 4096 == 0 and time.monotonic() > self.deadline:
            raise LimitExceeded(f"analysis exceeded {DEADLINE_SECONDS:.0f} seconds", t.line, t.col)
        return t

    def expect_op(self, value: str) -> Tok:
        if not self.at_op(value):
            raise ParseError(f"expected '{value}', found {self.tok.value or self.tok.kind!r}", self.tok)
        return self.advance()

    def skip_nl(self) -> None:
        while self.tok.kind == "nl" or self.at_op(";"):
            self.advance()

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise LimitExceeded(f"nesting deeper than {MAX_DEPTH} levels", self.tok.line, self.tok.col)

    def leave(self) -> None:
        self.depth -= 1

    # -- blocks and statements -------------------------------------------------------
    def parse_file(self) -> Block:
        stmts = self.statements(top=True)
        return Block(stmts, line=1, col=1)

    def statements(self, top: bool = False) -> list:
        out = []
        self.skip_nl()
        while not self.at("eof") and not (not top and self.at_op("}")):
            if top and self.at_op("}"):
                self.problems.append((self.tok.line, "unbalanced '}'"))
                self.advance()
                self.skip_nl()
                continue
            start = self.i
            try:
                stmt = self.statement()
                out.append(stmt)
                if not (self.tok.kind in ("nl", "eof") or self.at_op(";", "}")):
                    raise ParseError(f"unexpected {self.tok.value!r}", self.tok)
            except ParseError as exc:
                out.append(self.recover(start, str(exc)))
            self.skip_nl()
        return out

    def recover(self, start: int, message: str) -> Opaque:
        """Skip to the end of the statement at this nesting level and keep going."""
        first = self.toks[start]
        self.problems.append((first.line, message))
        self.i = max(self.i, start)
        depth = 0
        moved = False
        while not self.at("eof"):
            t = self.tok
            if t.kind == "op" and t.value in "([{":
                depth += 1
            elif t.kind == "op" and t.value in ")]}":
                if depth == 0:
                    if t.value == "}":
                        break
                    self.advance()
                    moved = True
                    continue
                depth -= 1
            elif depth == 0 and (t.kind == "nl" or (t.kind == "op" and t.value == ";")):
                break
            self.advance()
            moved = True
        if not moved and not self.at("eof") and not self.at_op("}"):
            self.advance()
        return Opaque(message, line=first.line, col=first.col)

    def block(self) -> Block:
        t = self.expect_op("{")
        self.enter()
        try:
            stmts = self.statements()
        finally:
            self.leave()
        self.expect_op("}")
        return Block(stmts, line=t.line, col=t.col)

    def body(self) -> Block:
        """A block, or a single statement as the body of if/for/while."""
        self.skip_nl()
        if self.at_op("{"):
            return self.block()
        t = self.tok
        return Block([self.statement()], line=t.line, col=t.col)

    def statement(self):
        t = self.tok
        if self.at_op("@"):
            return self.annotated()
        if t.kind == "ident":
            if t.value in _STATEMENT_KEYWORDS:
                return self.keyword_statement()
            if t.value in _MODIFIERS or self.looks_like_declaration():
                return self.declaration()
        if self.at_op("{"):
            b = self.block()
            return ExprStmt(Closure([], b, line=b.line, col=b.col), line=t.line, col=t.col)
        return self.expression_statement()

    def annotated(self):
        t = self.expect_op("@")
        name = self.qualified_name()
        args, named = [], []
        if self.at_op("("):
            save = self.i
            try:
                args, named, _ = self.paren_args()
            except ParseError:
                self.i = save
                self.skip_balanced()
        self.skip_nl()
        target = None
        if not (self.at("eof") or self.at_op("}")):
            target = self.statement()
        return Annotated(name, args, named, target, line=t.line, col=t.col)

    def qualified_name(self) -> str:
        if self.tok.kind != "ident":
            raise ParseError("expected a name", self.tok)
        parts = [self.advance().value]
        while self.at_op(".") and self.peek().kind == "ident":
            self.advance()
            parts.append(self.advance().value)
        return ".".join(parts)

    def looks_like_declaration(self) -> bool:
        """`String x = ...`, `List<String> xs`, `int n`: a type followed by a name."""
        t = self.tok
        if not (t.value[:1].isupper() or t.value in _PRIMITIVES):
            return False
        last = len(self.toks) - 1

        def at(j: int) -> Tok:        # the token at j, or the final eof token past the end
            return self.toks[min(j, last)]

        j = self.i + 1
        while at(j).kind == "op" and at(j).value == "." and at(j + 1).kind == "ident":
            j += 2
        if at(j).kind == "op" and at(j).value == "<":
            # A generic type argument list is short and stays on one line; give up early otherwise,
            # so `a < b; a < b; ...` cannot make this lookahead quadratic.
            depth, start = 0, j
            while True:
                v = at(j)
                if v.kind == "op" and v.value == "<":
                    depth += 1
                elif v.kind == "op" and v.value in (">", ">>", ">>>"):
                    depth -= len(v.value)
                    if depth <= 0:
                        j += 1
                        break
                elif v.kind in ("nl", "eof") or (v.kind == "op" and v.value in (";", "{", "}", "(", ")", "=")) \
                        or j - start > 64:
                    return False
                j += 1
        while at(j).kind == "op" and at(j).value == "[" and at(j + 1).value == "]":
            j += 2
        nxt, after = at(j), at(j + 1)
        return nxt.kind == "ident" and (after.kind in ("nl", "eof") or after.value in ("=", "(", ";", "}"))

    def skip_type(self) -> None:
        self.qualified_name()
        if self.at_op("<"):
            depth = 0
            while not self.at("eof"):
                v = self.advance()
                if v.kind == "op" and v.value == "<":
                    depth += 1
                elif v.kind == "op" and v.value in (">", ">>", ">>>"):
                    depth -= len(v.value)
                    if depth <= 0:
                        break
        while self.at_op("[") and self.peek().value == "]":
            self.advance()
            self.advance()

    def declaration(self):
        t = self.tok
        while self.tok.kind == "ident" and self.tok.value in _MODIFIERS:
            self.advance()
        if self.at_op("("):
            # def (a, b) = ...
            self.advance()
            names = []
            while not self.at_op(")") and not self.at("eof"):
                if self.tok.kind == "ident":
                    names.append(self.tok.value)
                self.advance()
            self.expect_op(")")
            value = None
            if self.at_op("="):
                self.advance()
                self.skip_nl()
                value = self.value()
            return Decl(",".join(names), value, line=t.line, col=t.col)
        if self.tok.kind == "ident" and (self.peek().kind == "ident" or self.looks_like_declaration()):
            self.skip_type()
        if self.tok.kind == "str" and self.peek().kind == "op" and self.peek().value == "(":
            name = self.advance().literal()        # def "method name"() { }
        elif self.tok.kind == "ident":
            name = self.advance().value
        else:
            raise ParseError("expected a name", self.tok)
        if self.at_op("("):
            params = self.param_list()
            self.skip_nl()
            if self.at("ident", "throws"):
                while not self.at_op("{") and not self.at("eof"):
                    self.advance()
            body = self.block()
            return MethodDef(name, params, body, line=t.line, col=t.col)
        value = None
        if self.at_op("="):
            self.advance()
            self.skip_nl()
            value = self.value()
        while self.at_op(","):          # int a = 1, b = 2
            self.advance()
            if self.tok.kind == "ident":
                self.advance()
            if self.at_op("="):
                self.advance()
                self.expr()
        return Decl(name, value, line=t.line, col=t.col)

    def param_list(self) -> list[str]:
        self.expect_op("(")
        names: list[str] = []
        depth = 0
        last_ident = None
        while not self.at("eof"):
            if self.at_op("(", "[", "{"):
                depth += 1
            elif self.at_op(")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and self.at_op(","):
                if last_ident:
                    names.append(last_ident)
                last_ident = None
            elif depth == 0 and self.at_op("="):
                if last_ident:
                    names.append(last_ident)
                last_ident = None
                depth_skip = 0
                self.advance()
                while not self.at("eof"):
                    if self.at_op("(", "[", "{"):
                        depth_skip += 1
                    elif self.at_op(")", "]", "}"):
                        if depth_skip == 0:
                            break
                        depth_skip -= 1
                    elif depth_skip == 0 and self.at_op(","):
                        break
                    self.advance()
                continue
            elif self.tok.kind == "ident":
                last_ident = self.tok.value
            self.advance()
        if last_ident:
            names.append(last_ident)
        self.expect_op(")")
        return names

    def keyword_statement(self):
        t = self.advance()
        kw = t.value
        if kw in ("import", "package"):
            parts = []
            while not (self.tok.kind in ("nl", "eof") or self.at_op(";", "}")):
                parts.append(self.advance().value)
            return Import("".join(parts), line=t.line, col=t.col)
        if kw == "if":
            self.expect_op("(")
            self.skip_nl()
            cond = self.expr()
            self.skip_nl()
            self.expect_op(")")
            then = self.body()
            otherwise = None
            save = self.i
            self.skip_nl()
            if self.at("ident", "else"):
                self.advance()
                self.skip_nl()
                if self.at("ident", "if"):
                    s = self.tok
                    otherwise = Block([self.keyword_statement()], line=s.line, col=s.col)
                else:
                    otherwise = self.body()
            else:
                self.i = save
            return If(cond, then, otherwise, line=t.line, col=t.col)
        if kw in ("for", "while"):
            header = self.paren_header()
            return Loop(header, self.body(), line=t.line, col=t.col)
        if kw == "do":
            body = self.body()
            self.skip_nl()
            if self.at("ident", "while"):
                self.advance()
                header = self.paren_header()
            else:
                header = []
            return Loop(header, body, line=t.line, col=t.col)
        if kw == "try":
            body = self.block()
            handlers, kinds = [], []
            while True:
                save = self.i
                self.skip_nl()
                if self.at("ident", "catch"):
                    self.advance()
                    self.paren_header()
                    handlers.append(self.block())
                    kinds.append("catch")
                elif self.at("ident", "finally"):
                    self.advance()
                    handlers.append(self.block())
                    kinds.append("finally")
                else:
                    self.i = save
                    break
            return Try(body, handlers, kinds, line=t.line, col=t.col)
        if kw == "switch":
            header = self.paren_header()
            subject = header[0] if header else Opaque("switch", line=t.line, col=t.col)
            self.skip_nl()
            self.expect_op("{")
            self.enter()
            cases: list[Block] = []
            try:
                self.skip_nl()
                while not self.at_op("}") and not self.at("eof"):
                    if self.at("ident", "case") or self.at("ident", "default"):
                        c = self.advance()
                        if c.value == "case":
                            self.expr()
                        self.expect_op(":")
                        stmts = []
                        self.skip_nl()
                        while not (self.at("ident", "case") or self.at("ident", "default") or self.at_op("}")
                                   or self.at("eof")):
                            start = self.i
                            try:
                                stmts.append(self.statement())
                            except ParseError as exc:
                                stmts.append(self.recover(start, str(exc)))
                            self.skip_nl()
                        cases.append(Block(stmts, line=c.line, col=c.col))
                    else:
                        start = self.i
                        try:
                            self.statement()
                        except ParseError as exc:
                            self.recover(start, str(exc))
                        self.skip_nl()
            finally:
                self.leave()
            self.expect_op("}")
            return Switch(subject, cases, line=t.line, col=t.col)
        if kw in ("return", "throw"):
            value = None
            if not (self.tok.kind in ("nl", "eof") or self.at_op(";", "}")):
                value = self.value()
            return Return(value, line=t.line, col=t.col, throw=kw == "throw")
        if kw in ("break", "continue"):
            if self.tok.kind == "ident":
                self.advance()
            return Return(None, line=t.line, col=t.col)
        if kw == "assert":
            value = self.expr()
            if self.at_op(":"):
                self.advance()
                self.expr()
            return ExprStmt(value, line=t.line, col=t.col)
        if kw in ("class", "interface", "enum", "trait"):
            name = self.advance().value if self.tok.kind == "ident" else "?"
            while not self.at_op("{") and not self.at("eof"):
                self.advance()
            if kw == "enum":
                self.skip_balanced()
                return ClassDef(name, Block([], line=t.line, col=t.col), line=t.line, col=t.col)
            body = self.block()
            return ClassDef(name, body, line=t.line, col=t.col)
        raise ParseError(f"unsupported statement {kw!r}", t)

    def skip_balanced(self) -> None:
        """Skip from an opening bracket to its match."""
        depth = 0
        while not self.at("eof"):
            v = self.advance()
            if v.kind == "op" and v.value in "([{":
                depth += 1
            elif v.kind == "op" and v.value in ")]}":
                depth -= 1
                if depth <= 0:
                    return

    def paren_header(self) -> list:
        """The parenthesized part of for/while/catch: kept as expressions where they parse."""
        self.expect_op("(")
        self.enter()
        out = []
        try:
            depth = 0
            start = self.i
            while not self.at("eof"):
                if self.at_op("(", "[", "{"):
                    depth += 1
                elif self.at_op(")", "]", "}"):
                    if depth == 0:
                        break
                    depth -= 1
                self.advance()
            end = self.i
            save = self.i
            self.i = start
            try:
                while self.i < end:
                    if self.at_op(";", ":") or self.tok.kind == "nl":
                        self.advance()
                        continue
                    if self.tok.kind == "ident" and (self.tok.value in _MODIFIERS or self.looks_like_declaration()):
                        while self.tok.kind == "ident" and self.peek().kind == "ident":
                            self.advance()
                    out.append(self.expr())
                    if self.i > end:
                        break
            except ParseError:
                pass
            self.i = save
        finally:
            self.leave()
        self.expect_op(")")
        return out

    def expression_statement(self):
        t = self.tok
        expr = self.expr()
        if self.tok.kind == "op" and self.tok.value in _ASSIGN:
            op = self.advance().value
            self.skip_nl()
            value = self.value()
            return Assign(expr, op, value, line=t.line, col=t.col)
        if self.starts_command_args(expr):
            args, named = self.command_args()
            closure = None
            if self.at_op("{"):
                closure = self.block()
            expr = Call(expr, args, named, closure, command=True, line=expr.line, col=expr.col)
        return ExprStmt(expr, line=t.line, col=t.col)

    def value(self):
        """An expression, or a command call used as a value: `def out = sh script: 'x', returnStdout: true`."""
        expr = self.expr()
        if self.starts_command_args(expr):
            args, named = self.command_args()
            closure = self.block() if self.at_op("{") else None
            expr = Call(expr, args, named, closure, command=True, line=expr.line, col=expr.col)
        return expr

    def starts_command_args(self, expr) -> bool:
        """`sh 'make'`, `agent any`, `label "x"`: a name followed by arguments on the same line."""
        if not isinstance(expr, (Name, Prop)) and not (isinstance(expr, Call) and not expr.command):
            return False
        t = self.tok
        if t.kind in ("str", "num"):
            return True
        if t.kind == "ident":
            return t.value not in _NOT_ARG_WORDS and t.value not in _BINARY_WORDS
        if t.kind == "op" and t.value in ("[", "!") :
            return isinstance(expr, (Name, Prop))
        if t.kind == "op" and t.value == "-" and self.peek().kind == "num":
            return isinstance(expr, (Name, Prop))
        return False

    def command_args(self) -> tuple[list, list]:
        args, named = [], []
        while True:
            self.argument(args, named)
            if self.at_op(","):
                self.advance()
                self.skip_nl()
                continue
            break
        return args, named

    # -- expressions -------------------------------------------------------------------
    def expr(self):
        self.enter()
        try:
            cond = self.binary()
            if self.at_op("?"):
                t = self.advance()
                self.skip_nl()
                then = self.expr()
                self.skip_nl()
                self.expect_op(":")
                self.skip_nl()
                otherwise = self.expr()
                return Ternary(cond, then, otherwise, line=t.line, col=t.col)
            return cond
        finally:
            self.leave()

    def binary(self, min_prec: int = 1):
        """Precedence climbing over Groovy's binary operators (tightest last in _PRECEDENCE)."""
        left = self.unary()
        while True:
            t = self.tok
            if (t.kind == "op" and t.value in _BINARY) or (t.kind == "ident" and t.value in _BINARY_WORDS):
                op, width = t.value, 1
            elif t.kind == "op" and t.value == "!" and self.peek().kind == "ident" and self.peek().value in (
                    "in", "instanceof"):
                op, width = "!" + self.peek().value, 2
            else:
                return left
            prec = _PRECEDENCE.get(op, 8)
            if prec < min_prec:
                return left
            for _ in range(width):
                self.advance()
            self.skip_nl_in_expr()
            if op in ("instanceof", "!instanceof", "as"):
                self.skip_type()
                right = Name("type", line=t.line, col=t.col)
            elif op == "**":           # right-associative
                self.enter()
                try:
                    right = self.binary(prec)
                finally:
                    self.leave()
            else:
                right = self.binary(prec + 1)
            left = Binary(op, left, right, line=t.line, col=t.col)

    def skip_nl_in_expr(self) -> None:
        while self.tok.kind == "nl":
            self.advance()

    def unary(self):
        t = self.tok
        if t.kind == "op" and t.value in ("!", "-", "+", "~", "++", "--", "*"):
            self.advance()
            return Unary(t.value, self.unary(), line=t.line, col=t.col)
        if t.kind == "ident" and t.value == "new":
            self.advance()
            name = self.qualified_name()
            if self.at_op("<"):
                depth = 0
                while not self.at("eof"):
                    v = self.advance()
                    if v.value == "<":
                        depth += 1
                    elif v.value in (">", ">>"):
                        depth -= len(v.value)
                        if depth <= 0:
                            break
            node = Name("new " + name, line=t.line, col=t.col)
            if self.at_op("["):
                self.advance()
                if not self.at_op("]"):
                    self.expr()
                self.expect_op("]")
                if self.at_op("{"):
                    self.block()
                return Call(node, line=t.line, col=t.col)
            return self.postfix(node)
        if t.kind == "op" and t.value == "(" and self.is_cast():
            self.advance()
            self.skip_type()
            self.expect_op(")")
            return self.unary()
        return self.postfix(self.primary())

    def is_cast(self) -> bool:
        a, b = self.peek(1), self.peek(2)
        if a.kind != "ident" or not (a.value[:1].isupper() or a.value in _PRIMITIVES):
            return False
        if not (b.kind == "op" and b.value == ")"):
            return False
        c = self.peek(3)
        return c.kind in ("ident", "str", "num") or (c.kind == "op" and c.value in ("(", "["))

    def primary(self):
        t = self.tok
        if t.kind == "ident":
            self.advance()
            return Name(t.value, line=t.line, col=t.col)
        if t.kind == "str":
            self.advance()
            return Str(t, line=t.line, col=t.col)
        if t.kind == "num":
            self.advance()
            return Num(t.value, line=t.line, col=t.col)
        if t.kind == "op":
            if t.value == "(":
                self.advance()
                self.enter()
                try:
                    self.skip_nl()
                    inner = self.expr()
                    self.skip_nl()
                finally:
                    self.leave()
                self.expect_op(")")
                return inner
            if t.value == "[":
                return self.list_or_map()
            if t.value == "{":
                return self.closure()
            if t.value == "@":           # annotation inside an expression: skip it
                self.advance()
                self.qualified_name()
                if self.at_op("("):
                    self.paren_args()
                return self.primary()
        raise ParseError(f"unexpected {t.value or t.kind!r}", t)

    def closure(self) -> Closure:
        t = self.expect_op("{")
        params: list[str] = []
        j = self.i
        names = []
        while self.toks[j].kind in ("ident", "nl") or (self.toks[j].kind == "op" and self.toks[j].value in (",",)):
            if self.toks[j].kind == "ident":
                names.append(self.toks[j].value)
            j += 1
        if self.toks[j].kind == "op" and self.toks[j].value == "->":
            params = [n for n in names if n not in _MODIFIERS and not n[:1].isupper()]
            self.i = j + 1
        self.enter()
        try:
            stmts = self.statements()
        finally:
            self.leave()
        self.expect_op("}")
        return Closure(params, Block(stmts, line=t.line, col=t.col), line=t.line, col=t.col)

    def list_or_map(self):
        t = self.expect_op("[")
        self.enter()
        try:
            self.skip_nl()
            if self.at_op(":") and self.peek().kind == "op" and self.peek().value == "]":
                self.advance()
                self.advance()
                return MapLit([], line=t.line, col=t.col)
            items, entries = [], []
            while not self.at_op("]"):
                key = self.map_key()
                if key is not None:
                    self.skip_nl()
                    entries.append((key, self.expr()))
                elif self.at_op("*") and self.peek().kind == "op" and self.peek().value == ":":
                    self.advance()
                    self.advance()
                    entries.append(("*", self.expr()))
                else:
                    items.append(self.expr())
                self.skip_nl()
                if self.at_op(","):
                    self.advance()
                    self.skip_nl()
                    continue
                if not self.at_op("]"):
                    raise ParseError(f"expected ',' or ']', found {self.tok.value!r}", self.tok)
            self.advance()
        finally:
            self.leave()
        if entries and not items:
            return MapLit(entries, line=t.line, col=t.col)
        return ListLit(items + [v for _, v in entries], line=t.line, col=t.col)

    def map_key(self):
        """A literal key followed by ':' (ident, string or number), or a (expression) key."""
        t, nxt = self.tok, self.peek()
        if t.kind in ("ident", "str", "num") and nxt.kind == "op" and nxt.value == ":":
            self.advance()
            self.advance()
            return t.literal() if t.kind == "str" else t.value
        if t.kind == "op" and t.value == "(":
            save = self.i
            try:
                self.advance()
                key = self.expr()
                self.expect_op(")")
                if self.at_op(":"):
                    self.advance()
                    return key
            except ParseError:
                pass
            self.i = save
        return None

    def postfix(self, node):
        while True:
            t = self.tok
            if t.kind == "op" and t.value in (".", "?.", "*.", ".&", ".@"):
                self.advance()
                self.skip_nl()
                m = self.tok
                if m.kind == "ident":
                    self.advance()
                    node = Prop(node, m.value, line=m.line, col=m.col)
                elif m.kind == "str":
                    self.advance()
                    node = Prop(node, m.literal(), line=m.line, col=m.col)
                elif m.kind == "op" and m.value == "(":     # .() calls
                    node = Prop(node, "call", line=m.line, col=m.col)
                else:
                    raise ParseError("expected a member name", m)
                continue
            if t.kind == "op" and t.value == "(" and self.same_line_as_previous():
                args, named, closure = self.paren_args()
                node = Call(node, args, named, closure, line=node.line, col=node.col)
                continue
            if t.kind == "op" and t.value == "[" and self.same_line_as_previous() and not isinstance(node, Call) \
                    or (t.kind == "op" and t.value == "[" and isinstance(node, Call) and not node.command
                        and self.same_line_as_previous() and self.adjacent()):
                self.advance()
                self.enter()
                try:
                    self.skip_nl()
                    index = self.expr() if not self.at_op("]") else Opaque("empty index", line=t.line, col=t.col)
                    while self.at_op(","):
                        self.advance()
                        self.expr()
                    self.skip_nl()
                finally:
                    self.leave()
                self.expect_op("]")
                node = Index(node, index, line=t.line, col=t.col)
                continue
            if t.kind == "op" and t.value == "{" and self.same_line_as_previous() and isinstance(
                    node, (Name, Prop, Call)):
                block = self.closure().body
                if isinstance(node, Call) and node.closure is None:
                    node.closure = block
                else:
                    node = Call(node, [], [], block, line=node.line, col=node.col)
                continue
            if t.kind == "op" and t.value in ("++", "--"):
                self.advance()
                continue
            return node

    def same_line_as_previous(self) -> bool:
        prev = self.toks[self.i - 1] if self.i > 0 else None
        return prev is None or prev.kind != "nl"

    def adjacent(self) -> bool:
        prev = self.toks[self.i - 1]
        return prev.line == self.tok.line

    def paren_args(self) -> tuple[list, list, Block | None]:
        self.expect_op("(")
        self.enter()
        args, named = [], []
        try:
            self.skip_nl()
            while not self.at_op(")"):
                self.argument(args, named)
                self.skip_nl()
                if self.at_op(","):
                    self.advance()
                    self.skip_nl()
                    continue
                if not self.at_op(")"):
                    raise ParseError(f"expected ',' or ')', found {self.tok.value!r}", self.tok)
        finally:
            self.leave()
        self.expect_op(")")
        closure = None
        if self.at_op("{") and self.same_line_as_previous():
            closure = self.closure().body
        return args, named, closure

    def argument(self, args: list, named: list) -> None:
        t, nxt = self.tok, self.peek()
        if t.kind in ("ident", "str") and nxt.kind == "op" and nxt.value == ":":
            self.advance()
            self.advance()
            self.skip_nl()
            named.append((t.literal() if t.kind == "str" else t.value, self.expr()))
            return
        if t.kind == "op" and t.value == "*" and nxt.kind == "op" and nxt.value == ":":
            self.advance()
            self.advance()
            named.append(("*", self.expr()))
            return
        args.append(self.expr())


# ---------------------------------------------------------------------------- entry
@dataclass
class ParseResult:
    tree: Block | None
    problems: list           # (line, message): statements recorded as Opaque
    error: str | None = None  # the file could not be analyzed at all


def parse(text: str, *, deadline: float | None = None) -> ParseResult:
    deadline = deadline or (time.monotonic() + DEADLINE_SECONDS)
    try:
        tokens = tokenize(text, deadline)
        parser = Parser(tokens, deadline)
        tree = parser.parse_file()
        return ParseResult(tree, parser.problems)
    except LimitExceeded as exc:
        return ParseResult(None, [], f"not analyzed: {exc}")
    except LexError as exc:
        return ParseResult(None, [], f"cannot be read: {exc}")
    except RecursionError:
        return ParseResult(None, [], "not analyzed: nesting too deep")
