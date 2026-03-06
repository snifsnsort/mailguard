"""
Domain Proximity / Lookalike Detection Engine

Detects typosquatted, homoglyph, and sound-alike domains that could be used
for phishing, BEC, or brand impersonation attacks.

Detection algorithms:
  - Levenshtein distance
  - Damerau-Levenshtein distance (handles adjacent transpositions)
  - Jaro-Winkler similarity
  - Character n-gram similarity (bigram + trigram, Jaccard coefficient)
    Jaccard chosen over cosine: simpler, interpretable, no vector math needed,
    performs equivalently for short strings like domain names.
  - Keyboard adjacency typos (QWERTY layout)
  - Unicode homoglyph normalization + mixed-script detection
  - Phonetic similarity (Metaphone chosen over Soundex:
    Metaphone handles more consonant patterns and performs better on
    non-Anglo names and technical terms common in company/domain names.)
  - TLD substitution detection
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── Homoglyph map ─────────────────────────────────────────────────────────────
# Maps visually similar Unicode chars → ASCII equivalent
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "n",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Latin lookalikes
    "ℓ": "l", "ı": "i", "ĺ": "l", "ļ": "l", "ľ": "l",
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "ý": "y", "ÿ": "y",
    "ñ": "n", "ç": "c",
    # Digits as letters
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "8": "b",
    # Special
    "ß": "ss", "æ": "ae", "œ": "oe",
    "rn": "m",  # digraph lookalike
}

# QWERTY keyboard adjacency map
QWERTY: Dict[str, str] = {
    "q": "wa",   "w": "qase", "e": "wsdr", "r": "edft", "t": "rfgy",
    "y": "tghu", "u": "yhji", "i": "ujko", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "aedxzw","d": "serfxc","f": "drtgvc","g": "ftyhbv",
    "h": "gyujnb","j": "huikmn","k": "jiolm", "l": "kop",
    "z": "asx",  "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
    "1": "2q",   "2": "13wq", "3": "24ew", "4": "35re", "5": "46tr",
    "6": "57yt", "7": "68uy", "8": "79iu", "9": "80oi", "0": "9po",
}

# Common TLD substitutions used in squatting
TLD_SUBSTITUTIONS = [
    ".com", ".net", ".org", ".io", ".co", ".app", ".dev",
    ".online", ".site", ".info", ".biz", ".us", ".ca",
    ".cc", ".email", ".mail", ".cloud", ".ai",
]

# Default scoring weights (sum to 1.0)
DEFAULT_WEIGHTS = {
    "levenshtein":    0.15,
    "damerau":        0.15,
    "jaro_winkler":   0.20,
    "ngram2":         0.10,
    "ngram3":         0.08,
    "keyboard_typo":  0.12,
    "homoglyph":      0.12,
    "phonetic":       0.08,
}

# Score thresholds
THRESHOLD_FLAG   = 70   # definitely suspicious
THRESHOLD_REVIEW = 45   # worth reviewing
THRESHOLD_IGNORE = 20   # probably fine


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class DomainSignals:
    levenshtein:   float = 0.0
    damerau:       float = 0.0
    jaro_winkler:  float = 0.0
    ngram2:        float = 0.0
    ngram3:        float = 0.0
    keyboard_typo: float = 0.0
    homoglyph:     float = 0.0
    phonetic:      float = 0.0


@dataclass
class LookalikMatch:
    candidate:      str
    base_domain:    str
    overall_score:  int           # 0-100
    risk_level:     str           # "flag" | "review" | "ignore"
    signals:        DomainSignals = field(default_factory=DomainSignals)
    reasons:        List[str]     = field(default_factory=list)
    has_homoglyphs: bool = False
    mixed_script:   bool = False
    tld_swap:       bool = False


# ── Normalization ─────────────────────────────────────────────────────────────

def normalize_domain(domain: str) -> Tuple[str, str, str]:
    """
    Returns (full_normalized, registered_label, tld).
    - Strips scheme, www., trailing dots/slashes
    - Lowercases
    - Decodes punycode (xn--) to Unicode for homoglyph analysis
    - Splits eTLD+1 from subdomain
    Assumptions:
      - We treat the last two labels as tld+registered (e.g. co.uk not handled — use eTLD+1 lib for production)
      - Subdomains are stripped for scoring but noted
    """
    domain = domain.lower().strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"/.*$", "", domain)
    domain = domain.strip(".")

    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]

    # Decode punycode labels
    labels = domain.split(".")
    decoded_labels = []
    for label in labels:
        try:
            decoded_labels.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except Exception:
            decoded_labels.append(label)

    full = ".".join(decoded_labels)
    if len(decoded_labels) >= 2:
        tld = decoded_labels[-1]
        registered = decoded_labels[-2]
    else:
        tld = ""
        registered = full

    return full, registered, tld


def strip_homoglyphs(s: str) -> Tuple[str, bool, bool]:
    """
    Returns (ascii_normalized, had_homoglyphs, mixed_script).
    Applies digraph substitutions first, then single-char map.
    """
    had_homoglyphs = False
    mixed_script = False

    # Check for mixed scripts (e.g. Latin + Cyrillic)
    scripts = set()
    for ch in s:
        cat = unicodedata.category(ch)
        if cat.startswith("L"):
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name:
                scripts.add("cyrillic")
            elif "GREEK" in name:
                scripts.add("greek")
            elif "LATIN" in name or ch.isascii():
                scripts.add("latin")
    if len(scripts) > 1:
        mixed_script = True
        had_homoglyphs = True

    # Apply digraph map
    result = s
    for src, dst in HOMOGLYPH_MAP.items():
        if len(src) > 1 and src in result:
            result = result.replace(src, dst)
            had_homoglyphs = True

    # Apply single char map
    out = []
    for ch in result:
        if ch in HOMOGLYPH_MAP and len(HOMOGLYPH_MAP[ch]) == 1:
            if ch != HOMOGLYPH_MAP[ch]:
                had_homoglyphs = True
            out.append(HOMOGLYPH_MAP[ch])
        else:
            out.append(ch)
    return "".join(out), had_homoglyphs, mixed_script


# ── Algorithm implementations ─────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            temp = dp[j]
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev + (0 if ca == cb else 1))
            prev = temp
    return dp[len(b)]


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (restricted edit distance)."""
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1): dp[i][0] = i
    for j in range(lb + 1): dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,
                dp[i][j-1] + 1,
                dp[i-1][j-1] + cost,
            )
            if i > 1 and j > 1 and a[i-1] == b[j-2] and a[i-2] == b[j-1]:
                dp[i][j] = min(dp[i][j], dp[i-2][j-2] + cost)
    return dp[la][lb]


def jaro(a: str, b: str) -> float:
    if a == b: return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0: return 0.0
    match_dist = max(la, lb) // 2 - 1
    a_matches = [False] * la
    b_matches = [False] * lb
    matches = 0
    transpositions = 0
    for i in range(la):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, lb)
        for j in range(start, end):
            if b_matches[j] or a[i] != b[j]: continue
            a_matches[i] = b_matches[j] = True
            matches += 1
            break
    if matches == 0: return 0.0
    k = 0
    for i in range(la):
        if not a_matches[i]: continue
        while not b_matches[k]: k += 1
        if a[i] != b[k]: transpositions += 1
        k += 1
    return (matches/la + matches/lb + (matches - transpositions/2)/matches) / 3


def jaro_winkler(a: str, b: str, p: float = 0.1) -> float:
    j = jaro(a, b)
    prefix = 0
    for i in range(min(len(a), len(b), 4)):
        if a[i] == b[i]: prefix += 1
        else: break
    return j + prefix * p * (1 - j)


def ngram_jaccard(a: str, b: str, n: int) -> float:
    def ngrams(s: str) -> set:
        return {s[i:i+n] for i in range(len(s) - n + 1)}
    sa, sb = ngrams(a), ngrams(b)
    if not sa and not sb: return 1.0
    if not sa or not sb: return 0.0
    return len(sa & sb) / len(sa | sb)


def keyboard_typo_distance(a: str, b: str) -> int:
    """
    Count substitutions where the changed character is a QWERTY neighbor.
    Returns number of adjacent-key substitutions (lower = more suspicious).
    """
    if len(a) != len(b): return 999
    typos = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            neighbors = QWERTY.get(ca, "")
            if cb in neighbors:
                typos += 1
            else:
                return 999  # non-adjacent substitution — not a keyboard typo
    return typos


def metaphone(word: str) -> str:
    """
    Simplified Metaphone encoding for domain labels.
    Handles common English phonetic patterns.
    """
    word = word.upper()
    word = re.sub(r"[^A-Z]", "", word)
    if not word: return ""

    # Initial transformations
    word = re.sub(r"^(AE|GN|KN|PN|WR)", lambda m: m.group()[1:], word)
    word = re.sub(r"MB$", "M", word)

    result = []
    i = 0
    vowels = set("AEIOU")
    while i < len(word):
        ch = word[i]
        # Skip duplicate adjacent consonants
        if result and ch == result[-1] and ch not in vowels:
            i += 1; continue
        if ch in vowels:
            if i == 0: result.append(ch)
        elif ch == "B":
            result.append("B")
        elif ch == "C":
            if i+1 < len(word) and word[i+1] in "EIY":
                result.append("S")
            elif i+1 < len(word) and word[i:i+2] == "CH":
                result.append("X"); i += 1
            else:
                result.append("K")
        elif ch == "D":
            if i+1 < len(word) and word[i:i+2] == "DG" and i+2 < len(word) and word[i+2] in "EIY":
                result.append("J"); i += 1
            else:
                result.append("T")
        elif ch == "F": result.append("F")
        elif ch == "G":
            if i+1 < len(word) and word[i+1] in "EIY":
                result.append("J")
            elif i+1 < len(word) and word[i+1] == "H" and (i+2 >= len(word) or word[i+2] not in vowels):
                i += 1
            elif word[i:i+2] != "GN" and word[i:i+2] != "GH":
                result.append("K")
        elif ch == "H":
            if i+1 < len(word) and word[i+1] in vowels and (i == 0 or word[i-1] not in vowels):
                result.append("H")
        elif ch == "J": result.append("J")
        elif ch == "K":
            if i == 0 or word[i-1] != "C": result.append("K")
        elif ch == "L": result.append("L")
        elif ch == "M": result.append("M")
        elif ch == "N": result.append("N")
        elif ch == "P":
            if i+1 < len(word) and word[i+1] == "H": result.append("F"); i += 1
            else: result.append("P")
        elif ch == "Q": result.append("K")
        elif ch == "R": result.append("R")
        elif ch == "S":
            if word[i:i+2] in ("SH", "SI", "SU") and i+1 < len(word) and word[i+1] in "HIU":
                result.append("X")
            else: result.append("S")
        elif ch == "T":
            if word[i:i+2] == "TH": result.append("0")
            elif word[i:i+3] in ("TIA", "TIO"): result.append("X")
            else: result.append("T")
        elif ch == "V": result.append("F")
        elif ch == "W":
            if i+1 < len(word) and word[i+1] in vowels: result.append("W")
        elif ch == "X": result.extend(["K", "S"])
        elif ch == "Y":
            if i+1 < len(word) and word[i+1] in vowels: result.append("Y")
        elif ch == "Z": result.append("S")
        i += 1
    return "".join(result)


# ── Scoring ───────────────────────────────────────────────────────────────────

def _lev_similarity(dist: int, max_len: int) -> float:
    if max_len == 0: return 1.0
    return max(0.0, 1.0 - dist / max_len)


def score_pair(
    base: str,
    candidate: str,
    weights: Optional[Dict[str, float]] = None,
) -> LookalikMatch:
    if weights is None:
        weights = DEFAULT_WEIGHTS

    _, base_label, base_tld       = normalize_domain(base)
    _, cand_label_raw, cand_tld   = normalize_domain(candidate)

    # Homoglyph normalization
    cand_label_norm, had_hg, mixed = strip_homoglyphs(cand_label_raw)
    base_label_norm, _, _          = strip_homoglyphs(base_label)

    reasons: List[str] = []
    signals = DomainSignals()

    # 1. Levenshtein
    lev_dist = levenshtein(base_label_norm, cand_label_norm)
    max_len  = max(len(base_label_norm), len(cand_label_norm), 1)
    signals.levenshtein = _lev_similarity(lev_dist, max_len)
    if lev_dist == 1:
        reasons.append(f"One character edit from '{base_label}'")
    elif lev_dist == 2:
        reasons.append(f"Two character edits from '{base_label}'")

    # 2. Damerau-Levenshtein
    dam_dist = damerau_levenshtein(base_label_norm, cand_label_norm)
    signals.damerau = _lev_similarity(dam_dist, max_len)
    if dam_dist < lev_dist and dam_dist <= 1:
        reasons.append("Single adjacent transposition detected")

    # 3. Jaro-Winkler
    signals.jaro_winkler = jaro_winkler(base_label_norm, cand_label_norm)
    if signals.jaro_winkler > 0.92 and base_label_norm != cand_label_norm:
        reasons.append(f"Very high Jaro-Winkler similarity ({signals.jaro_winkler:.2f})")

    # 4. N-gram (bigram + trigram)
    signals.ngram2 = ngram_jaccard(base_label_norm, cand_label_norm, 2)
    signals.ngram3 = ngram_jaccard(base_label_norm, cand_label_norm, 3)
    if signals.ngram2 > 0.8:
        reasons.append(f"High bigram overlap ({signals.ngram2:.2f})")

    # 5. Keyboard typo
    if len(base_label_norm) == len(cand_label_norm):
        typo_count = keyboard_typo_distance(base_label_norm, cand_label_norm)
        if typo_count < 999:
            signals.keyboard_typo = 1.0 - (typo_count / max(len(base_label_norm), 1))
            if typo_count == 1:
                reasons.append("Single adjacent-key substitution (keyboard typo)")
            elif typo_count == 2:
                reasons.append(f"{typo_count} adjacent-key substitutions")
    # For length-mismatched, check if the base with one char inserted/deleted is a typo
    else:
        # Partial credit if very close and length differs by 1
        if abs(len(base_label_norm) - len(cand_label_norm)) == 1 and lev_dist == 1:
            signals.keyboard_typo = 0.7
            reasons.append("Character insertion/deletion — possible fat-finger")

    # 6. Homoglyph
    if had_hg:
        signals.homoglyph = 0.95
        if mixed:
            reasons.append("Mixed Unicode scripts detected — likely homoglyph attack")
        else:
            reasons.append("Unicode homoglyphs normalized — visually similar to base domain")
    elif base_label_norm != base_label and cand_label_norm == base_label_norm:
        signals.homoglyph = 0.9
        reasons.append("Homoglyph substitution makes domain visually identical")

    # 7. Phonetic (Metaphone)
    meta_base = metaphone(base_label_norm)
    meta_cand = metaphone(cand_label_norm)
    if meta_base and meta_cand:
        meta_lev = levenshtein(meta_base, meta_cand)
        signals.phonetic = _lev_similarity(meta_lev, max(len(meta_base), len(meta_cand), 1))
        if signals.phonetic > 0.85 and base_label_norm != cand_label_norm:
            reasons.append(f"Sounds similar phonetically (Metaphone: {meta_base} ≈ {meta_cand})")

    # TLD swap
    tld_swap = (base_tld != cand_tld and base_label_norm == cand_label_norm)
    if tld_swap:
        reasons.append(f"Same label, different TLD (.{base_tld} → .{cand_tld})")

    # ── Composite score ───────────────────────────────────────────────────────
    raw = sum(getattr(signals, k) * w for k, w in weights.items())
    # Boost for homoglyphs (high-confidence attack signal)
    if had_hg and mixed:
        raw = max(raw, 0.85)
    elif had_hg:
        raw = max(raw, 0.75)
    # Boost for TLD swap with identical label
    if tld_swap:
        raw = max(raw, 0.65)

    overall = min(100, round(raw * 100))

    if overall >= THRESHOLD_FLAG:
        risk = "flag"
    elif overall >= THRESHOLD_REVIEW:
        risk = "review"
    else:
        risk = "ignore"

    if not reasons:
        reasons.append("Low similarity — unlikely lookalike")

    return LookalikMatch(
        candidate=candidate,
        base_domain=base,
        overall_score=overall,
        risk_level=risk,
        signals=signals,
        reasons=reasons,
        has_homoglyphs=had_hg,
        mixed_script=mixed,
        tld_swap=tld_swap,
    )


def detect_lookalikes(
    base_domains: List[str],
    candidate_domains: List[str],
    weights: Optional[Dict[str, float]] = None,
    min_score: int = THRESHOLD_REVIEW,
) -> List[LookalikMatch]:
    """
    Score all candidate domains against all base domains.
    Returns matches above min_score, sorted by score descending.
    DNS resolution is NOT performed here — call detect_registered_lookalikes()
    for the full async pipeline that filters to only registered domains.
    """
    results: List[LookalikMatch] = []
    for base in base_domains:
        for cand in candidate_domains:
            _, b_label, _ = normalize_domain(base)
            _, c_label, _ = normalize_domain(cand)
            if b_label == c_label:
                continue
            match = score_pair(base, cand, weights)
            if match.overall_score >= min_score:
                results.append(match)
    results.sort(key=lambda m: m.overall_score, reverse=True)
    return results


# ── DNS resolution ────────────────────────────────────────────────────────────

import asyncio
import dns.asyncresolver

@dataclass
class DnsInfo:
    domain: str
    has_a:      bool = False
    has_mx:     bool = False
    a_records:  List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)

    @property
    def is_registered(self) -> bool:
        return self.has_a or self.has_mx


async def _resolve_domain(domain: str, semaphore: asyncio.Semaphore) -> DnsInfo:
    info = DnsInfo(domain=domain)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 4

    async with semaphore:
        # Check A records
        try:
            ans = await resolver.resolve(domain, "A")
            info.a_records = [str(r) for r in ans]
            info.has_a = True
        except Exception:
            pass

        # Check MX records
        try:
            ans = await resolver.resolve(domain, "MX")
            info.mx_records = [str(r.exchange).rstrip(".") for r in ans]
            info.has_mx = True
        except Exception:
            pass

    return info


async def resolve_domains_bulk(domains: List[str], concurrency: int = 50) -> Dict[str, DnsInfo]:
    """
    Resolve A and MX records for a list of domains concurrently.
    Returns dict of domain -> DnsInfo.
    Limits concurrency to avoid flooding DNS resolvers.
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_resolve_domain(d, semaphore) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        r.domain: r
        for r in results
        if isinstance(r, DnsInfo)
    }


async def detect_registered_lookalikes(
    base_domains: List[str],
    candidate_domains: List[str],
    weights: Optional[Dict[str, float]] = None,
    min_score: int = THRESHOLD_REVIEW,
    concurrency: int = 50,
) -> Tuple[List[LookalikMatch], Dict[str, DnsInfo]]:
    """
    Full pipeline:
    1. Score all candidates against base domains
    2. Keep only those above min_score
    3. Resolve DNS for scored candidates
    4. Filter to only domains with A or MX records
    5. Return (matches, dns_info_map) sorted by score descending

    Returns only REGISTERED lookalikes (domains that resolve in DNS).
    """
    # Step 1+2: Score first to avoid resolving thousands of low-scoring domains
    scored = detect_lookalikes(base_domains, candidate_domains, weights, min_score)

    if not scored:
        return [], {}

    # Step 3: Resolve DNS only for scored candidates
    unique_candidates = list({m.candidate for m in scored})
    dns_map = await resolve_domains_bulk(unique_candidates, concurrency)

    # Step 4: Filter to registered only
    registered = [
        m for m in scored
        if dns_map.get(m.candidate, DnsInfo(domain=m.candidate)).is_registered
    ]

    # Annotate with DNS info in reasons
    for m in registered:
        info = dns_map.get(m.candidate)
        if info:
            dns_details = []
            if info.has_a:
                dns_details.append(f"A: {', '.join(info.a_records[:3])}")
            if info.has_mx:
                dns_details.append(f"MX: {', '.join(info.mx_records[:2])}")
            if dns_details:
                m.reasons.append(f"Registered in DNS — {'; '.join(dns_details)}")

    return registered, dns_map


def generate_common_squats(domain: str) -> List[str]:
    """
    Generate a list of common typosquat candidates for a domain.
    Used when no external feed is available.
    """
    _, label, tld = normalize_domain(domain)
    candidates = set()

    # TLD substitutions
    for alt_tld in TLD_SUBSTITUTIONS:
        alt = alt_tld.lstrip(".")
        if alt != tld:
            candidates.add(f"{label}.{alt}")

    # Character deletions
    for i in range(len(label)):
        candidates.add(f"{label[:i]}{label[i+1:]}.{tld}")

    # Adjacent keyboard substitutions
    for i, ch in enumerate(label):
        for neighbor in QWERTY.get(ch, ""):
            new_label = label[:i] + neighbor + label[i+1:]
            candidates.add(f"{new_label}.{tld}")

    # Character transpositions
    for i in range(len(label) - 1):
        new_label = label[:i] + label[i+1] + label[i] + label[i+2:]
        candidates.add(f"{new_label}.{tld}")

    # Character insertions (common additions)
    for i in range(len(label) + 1):
        for ch in "abcdefghijklmnopqrstuvwxyz-":
            candidates.add(f"{label[:i]}{ch}{label[i:]}.{tld}")

    # Common prefix/suffix additions (bare concat)
    for affix in ["my", "the", "get", "go", "secure", "mail", "web", "app", "portal", "online"]:
        candidates.add(f"{affix}{label}.{tld}")
        candidates.add(f"{label}{affix}.{tld}")

    # ── Hyphen-based attack patterns ──────────────────────────────────────────
    # Attackers abuse hyphens to make domains look like official brand pages.
    # These are split into semantic categories for clarity and coverage.

    # Category 1: Authentication & identity (prefix-brand attacks)
    AUTH_PREFIXES = [
        "login", "log-in", "signin", "sign-in", "logon", "log-on",
        "auth", "authenticate", "authentication",
        "sso", "oauth", "saml", "mfa", "2fa", "otp", "totp",
        "account", "accounts", "myaccount", "my-account",
        "user", "users", "profile", "id", "identity",
        "access", "secure-access", "get-access",
        "password", "passwd", "reset", "password-reset", "pwd-reset",
        "verify", "verification", "validate", "confirm",
    ]

    # Category 2: Security / alert (prefix-brand attacks)
    SECURITY_PREFIXES = [
        "security", "secure", "safety", "alert", "alerts",
        "notice", "notification", "notifications", "warning",
        "protect", "protection", "privacy",
        "phishing", "fraud", "suspicious",
    ]

    # Category 3: Service & billing (prefix-brand attacks)
    SERVICE_PREFIXES = [
        "billing", "invoice", "invoices", "payment", "pay", "payments",
        "checkout", "order", "orders", "receipt",
        "support", "help", "helpdesk", "helpcentre", "help-center",
        "service", "services", "contact", "customerservice", "customer-service",
        "care", "desk",
    ]

    # Category 4: Infrastructure / portal (prefix-brand attacks)
    INFRA_PREFIXES = [
        "portal", "web", "www", "app", "apps", "application",
        "api", "mail", "email", "webmail", "owa",
        "office", "teams", "admin", "manage", "management",
        "cdn", "static", "assets", "files", "cloud",
        "my", "go", "get", "connect",
    ]

    ALL_PREFIXES = AUTH_PREFIXES + SECURITY_PREFIXES + SERVICE_PREFIXES + INFRA_PREFIXES

    # Category 5: Suffixes (brand-suffix attacks — appear authoritative to users
    # who read left-to-right and see the brand name first)
    ALL_SUFFIXES = [
        "login", "auth", "signin", "access", "portal", "gateway",
        "online", "app", "web", "secure", "verify", "verification",
        "account", "accounts", "support", "help", "billing", "pay",
        "admin", "mail", "id", "sso", "hub", "center", "centre",
        "cloud", "connect", "home", "office", "now", "today",
    ]

    for prefix in ALL_PREFIXES:
        candidates.add(f"{prefix}-{label}.{tld}")
    for suffix in ALL_SUFFIXES:
        candidates.add(f"{label}-{suffix}.{tld}")

    # Category 6: Compound patterns — prefix-brand-suffix (triple component)
    # e.g. login-contoso-verify.com, secure-contoso-portal.com
    # Most convincing pattern — appears to describe a specific action on the brand
    COMPOUND_PREFIXES = ["login", "auth", "secure", "verify", "account", "signin", "support"]
    COMPOUND_SUFFIXES = ["verify", "portal", "access", "online", "app", "login", "secure", "now"]
    for cpfx in COMPOUND_PREFIXES:
        for csfx in COMPOUND_SUFFIXES:
            if cpfx != csfx:
                candidates.add(f"{cpfx}-{label}-{csfx}.{tld}")

    # Category 7: Domain keyword sandwich — brand wrapped in auth/service words
    # e.g. microsoft-login-verify.com, auth-contoso-access.com
    SANDWICH_MIDDLES = ["login", "auth", "account", "secure", "verify", "support"]
    for mid in SANDWICH_MIDDLES:
        candidates.add(f"{label}-{mid}-online.{tld}")
        candidates.add(f"{label}-{mid}-portal.{tld}")
        candidates.add(f"secure-{label}-{mid}.{tld}")

    # Category 8: Number substitutions in label (leet-speak style)
    # Commonly used to evade blocklists
    LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "g": "9", "l": "1"}
    for i, ch in enumerate(label):
        if ch in LEET:
            leet_label = label[:i] + LEET[ch] + label[i+1:]
            candidates.add(f"{leet_label}.{tld}")
            # Also combine with a hyphen prefix for realism
            candidates.add(f"login-{leet_label}.{tld}")

    # Category 9: Dot-replaced-with-hyphen patterns
    # Attackers register e.g. login-contoso-com.net to look like login.contoso.com
    candidates.add(f"login-{label}-{tld}.com")
    candidates.add(f"auth-{label}-{tld}.com")
    candidates.add(f"secure-{label}-{tld}.com")
    candidates.add(f"{label}-{tld}.com")    # e.g. contoso-com.net

    # Category 10: Subdomain-as-label (registering fqdn-lookalike domains)
    # Attackers register mail-contoso.com to mimic mail.contoso.com
    SUBDOMAIN_SIMULATIONS = [
        "mail", "owa", "autodiscover", "remote", "vpn", "webmail",
        "login", "sso", "auth", "portal", "admin", "helpdesk",
    ]
    for sub in SUBDOMAIN_SIMULATIONS:
        candidates.add(f"{sub}-{label}.{tld}")
        candidates.add(f"{sub}.{label}.{tld}")   # Actual subdomain candidate

    # Category 11: Pluralisation and common word mutations
    if not label.endswith("s"):
        candidates.add(f"{label}s.{tld}")
    if label.endswith("s"):
        candidates.add(f"{label[:-1]}.{tld}")
    candidates.add(f"{label}inc.{tld}")
    candidates.add(f"{label}-inc.{tld}")
    candidates.add(f"{label}corp.{tld}")
    candidates.add(f"{label}-corp.{tld}")
    candidates.add(f"{label}hq.{tld}")
    candidates.add(f"{label}-hq.{tld}")
    candidates.add(f"{label}group.{tld}")
    candidates.add(f"{label}-group.{tld}")


    # Remove the original and very short results
    candidates.discard(domain)
    candidates.discard(f"{label}.{tld}")
    return [c for c in candidates if len(c.split(".")[0]) >= 2]
