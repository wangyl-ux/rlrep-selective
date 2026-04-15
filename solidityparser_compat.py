import re

from antlr4 import CommonTokenStream, InputStream, Token
from antlr4.RuleContext import RuleContext
from antlr4.tree.Trees import Trees

from solidityparser.SolidityLexer import SolidityLexer


_FAULT_MARKER_RE = re.compile(r"\s*//\s*(?:fault|fixed)\s+line\s*$")


def _tree_to_code_sequence(cls, t, ruleNames=None, recog=None):
    if recog is not None:
        ruleNames = recog.ruleNames
    text = cls.getNodeText(t, ruleNames)
    text = "" if text is None else str(text)
    if t.getChildCount() == 0:
        return text
    children = [cls.toCodeSequence(t.getChild(i), ruleNames) for i in range(t.getChildCount())]
    return "{} {}".format(text, " ".join(children))


def ensure_antlr_extensions():
    if not hasattr(RuleContext, "toCodeSequence"):
        def _rule_context_to_code_sequence(self, ruleNames=None, recog=None):
            return Trees.toCodeSequence(self, ruleNames=ruleNames, recog=recog)

        RuleContext.toCodeSequence = _rule_context_to_code_sequence

    if not hasattr(Trees, "toCodeSequence"):
        Trees.toCodeSequence = classmethod(_tree_to_code_sequence)


def tokenize_code_fragment(code):
    sanitized = _FAULT_MARKER_RE.sub("", code).strip()
    if not sanitized:
        return []

    lexer = SolidityLexer(InputStream(sanitized))
    stream = CommonTokenStream(lexer)
    stream.fill()

    tokens = []
    for token in stream.tokens:
        if token.type == Token.EOF or token.channel != Token.DEFAULT_CHANNEL:
            continue
        text = token.text.strip()
        if text:
            tokens.append(text)
    return tokens


ensure_antlr_extensions()
