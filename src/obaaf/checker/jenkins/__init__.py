"""The Jenkins adapter of `obaaf check` (advisory).

parser.py reads Groovy as text with a syntax-only tokenizer and parser: it never compiles,
loads classes or evaluates expressions, so nothing in a Jenkinsfile runs (D-033).
"""
