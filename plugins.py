"""YOUR extension file — payloads and operators for the toolkit.

These are STARTERS. Replace/expand them with your team's own material — this is
where your differentiation lives. Nothing here is required; the engine just
needs at least one payload per category and one meaning-preserving operator.
"""

from toolkit.registry import payload, operator
from toolkit.models import Category, make_attack


# =========================================================================== #
# OPERATORS  — text transforms for the flip hunter + metamorphic oracle
#   meaning_preserving=True  -> a human calls it "the same sentence"
#                               (feeds BOTH the flip hunter and the oracle)
#   meaning_preserving=False -> meaning may change (flip hunter only)
# =========================================================================== #

# Latin -> visually identical Cyrillic. Human reads it the same; the model sees
# entirely different token IDs.
_HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "x": "х"}

@operator(name="homoglyph", meaning_preserving=True)
def homoglyph(text):
    for latin, cyr in _HOMOGLYPHS.items():
        if latin in text:
            yield text.replace(latin, cyr, 1)   # one swap per variant


# Insert an invisible zero-width space in the middle of the string. Invisible to
# a human, but it splits a token for the model.
@operator(name="zero_width", meaning_preserving=True)
def zero_width(text):
    if len(text) >= 2:
        mid = len(text) // 2
        yield text[:mid] + "\u200b" + text[mid:]


# Uppercase the string. Same words, same meaning; different tokenisation.
@operator(name="uppercase", meaning_preserving=True)
def uppercase(text):
    up = text.upper()
    if up != text:
        yield up


# =========================================================================== #
# PAYLOADS  — the static attack suite (the four rubric categories)
#   A factory returns one Attack or a list of Attacks. make_attack() ids them.
#   payload can be a str, or int/list/dict/None for type-confusion tests.
# =========================================================================== #

@payload(Category.MALFORMED)
def malformed():
    return [
        make_attack(Category.MALFORMED, "A" * 100_000, name="oversized_100k"),
        make_attack(Category.MALFORMED, "", name="empty_string"),
    ]


@payload(Category.BOUNDARY)          # type confusion — payload isn't a string
def boundary():
    return [
        make_attack(Category.BOUNDARY, 12345, name="int_not_str"),
        make_attack(Category.BOUNDARY, ["a", "b"], name="list_not_str"),
        make_attack(Category.BOUNDARY, None, name="null"),
    ]


@payload(Category.ENCODING)
def encoding():
    return [
        make_attack(Category.ENCODING, "good\u200b\u200bmovie", name="zero_width_split"),
        make_attack(Category.ENCODING, "🎬" * 500, name="emoji_flood"),
    ]


@payload(Category.ADVERSARIAL)
def adversarial():
    return [
        make_attack(Category.ADVERSARIAL, "great " * 200 + "terrible", name="repetition_swamp"),
    ]
_SYNONYMS = {
    "good": ["decent", "fine", "solid"],
    "bad": ["poor", "weak", "subpar"],
    "okay": ["ok", "alright", "acceptable"],
    "great": ["excellent", "superb"],
    "slow": ["sluggish", "unhurried"],
    "long": ["lengthy", "extended"],
}

@operator(name="synonym", meaning_preserving=True)
def synonym(text):
    for word, alts in _SYNONYMS.items():
        if word in text.split():
            for alt in alts:
                yield " ".join(alt if t == word else t for t in text.split())
