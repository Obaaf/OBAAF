"""Jenkins parser safety and coverage (Jenkins design, section 5; JT 02).

The parser reads Groovy as text. It never compiles, loads classes or evaluates expressions, so
annotations such as @Grab or @ASTTest, static initializers and dependency loading cannot run.
Hostile input must fail within the limits, as an analysis error, never as a crash or a hang.
"""

import time
import unittest

import helpers  # noqa: F401  (puts src on the path)

from obaaf.checker.jenkins import lexer, parser
from obaaf.checker.jenkins.parser import Binary, Call, Closure, Decl, ExprStmt, MethodDef, Str


def parse_ok(text):
    result = parser.parse(text)
    if result.error:
        raise AssertionError(result.error)
    return result


def show(node):
    """Binary trees as parenthesized text, to check precedence."""
    if isinstance(node, Binary):
        return f"({show(node.left)} {node.op} {show(node.right)})"
    if isinstance(node, Str):
        return repr(node.text())
    return getattr(node, "name", type(node).__name__)


class NothingRunsTest(unittest.TestCase):
    def test_compile_time_annotations_and_initializers_execute_nothing(self):
        # Each of these would run code if the file were compiled; the parser only tokenizes them.
        hostile = '''
@Grab('org.example:evil:1.0')
import org.example.Evil
@groovy.transform.ASTTest(value = { new File('/tmp/obaaf-pwned').text = 'x' })
def x = 1
class Boom { static { new File('/tmp/obaaf-pwned').text = 'static' } }
pipeline { agent any; stages { stage('a') { steps { sh 'true' } } } }
'''
        result = parse_ok(hostile)
        self.assertIsNotNone(result.tree)
        import os
        self.assertFalse(os.path.exists("/tmp/obaaf-pwned"))

    def test_the_parser_imports_no_code_execution_facility(self):
        import inspect
        source = inspect.getsource(lexer) + inspect.getsource(parser)
        for forbidden in ("eval(", "exec(", "subprocess", "compile(", "__import__", "socket", "urllib"):
            self.assertNotIn(forbidden, source)


class LimitsTest(unittest.TestCase):
    def assert_fast_error(self, text, words, seconds=5.0):
        start = time.monotonic()
        result = parser.parse(text)
        self.assertLess(time.monotonic() - start, seconds)
        self.assertIsNotNone(result.error)
        self.assertTrue(any(w in result.error for w in words), result.error)

    def test_deep_nesting_stops_at_the_limit(self):
        self.assert_fast_error("x = " + "(" * 5000 + "1" + ")" * 5000, ("nesting", "deep"))
        self.assert_fast_error("node { " * 3000 + "}" * 3000, ("nesting", "deep"))
        self.assert_fast_error("x = " + "[" * 5000 + "]" * 5000, ("nesting", "deep"))
        self.assert_fast_error("x = 1" + " ** 1" * 20000, ("nesting", "deep"))

    def test_large_files_are_not_analyzed(self):
        self.assert_fast_error("// x\n" * 300_000, ("not analyzed",))

    def test_token_floods_stop_at_the_token_limit(self):
        self.assert_fast_error("a;" * 450_000, ("not analyzed",), seconds=20)

    def test_blank_lines_are_linear(self):
        start = time.monotonic()
        result = parser.parse("\n" * 900_000 + "node { sh 'x' }")
        self.assertLess(time.monotonic() - start, 5)
        self.assertIsNone(result.error)

    def test_unterminated_strings_are_read_errors(self):
        for text in ('sh "abc', "sh '''abc", 'sh """abc ${', "x = /abc"):
            result = parser.parse(text)
            self.assertTrue(result.error is None or "cannot be read" in result.error, result.error)


class SyntaxTest(unittest.TestCase):
    def test_declarative_structure(self):
        tree = parse_ok("pipeline {\n agent any\n stages { stage('Build') { steps { sh 'make' } } }\n}").tree
        call = tree.stmts[0].expr
        self.assertIsInstance(call, Call)
        self.assertEqual(call.callee.name, "pipeline")

    def test_gstring_interpolation_parts(self):
        tree = parse_ok('sh "echo ${env.CHANGE_TITLE} and $BRANCH_NAME"').tree
        arg = tree.stmts[0].expr.args[0]
        self.assertTrue(arg.interpolated)
        self.assertEqual(arg.exprs, ["env.CHANGE_TITLE", "BRANCH_NAME"])

    def test_single_quotes_and_escaped_dollars_do_not_interpolate(self):
        for text in ("sh 'echo $CHANGE_TITLE'", 'sh "echo \\$CHANGE_TITLE"', "sh '''echo ${CHANGE_TITLE}'''"):
            arg = parse_ok(text).tree.stmts[0].expr.args[0]
            self.assertFalse(arg.interpolated, text)

    def test_operator_precedence(self):
        cases = {
            "x = a == 'm' || b == 'n' && c": "((a == 'm') || ((b == 'n') && c))",
            "x = 1 + 2 * 3 - 4": "((Num + (Num * Num)) - Num)",
            "x = a ** b ** c": "(a ** (b ** c))",
            "x = a ?: b || c": "(a ?: (b || c))",
            "x = a === b": "(a === b)",
        }
        for text, expected in cases.items():
            decl = parse_ok(text).tree.stmts[0]
            self.assertEqual(show(decl.value), expected, text)

    def test_method_definitions_and_closures(self):
        tree = parse_ok("boolean isMain() { return env.BRANCH_NAME == 'main' }\n"
                        "def b = { a, c -> sh 'x' }").tree
        self.assertIsInstance(tree.stmts[0], MethodDef)
        self.assertEqual(tree.stmts[0].name, "isMain")
        self.assertIsInstance(tree.stmts[1], Decl)
        self.assertIsInstance(tree.stmts[1].value, Closure)
        self.assertEqual(tree.stmts[1].value.params, ["a", "c"])

    def test_command_calls_and_named_arguments(self):
        tree = parse_ok("input message: 'Release?', submitter: 'release'\nsh(script: 'x', returnStdout: true)").tree
        first = tree.stmts[0].expr
        self.assertEqual(first.callee.name, "input")
        self.assertEqual([k for k, _ in first.named], ["message", "submitter"])
        self.assertIsInstance(tree.stmts[1], ExprStmt)

    def test_unknown_statements_are_recorded_not_dropped(self):
        result = parser.parse("node {\n  sh 'a'\n  ) ) )\n  sh 'b'\n}")
        self.assertIsNone(result.error)
        self.assertTrue(result.problems)


if __name__ == "__main__":
    unittest.main()
