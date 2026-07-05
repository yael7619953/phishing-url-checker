# A small set of frequently-impersonated domains. Extend this list as needed;
# it does not need to be exhaustive to be useful for a demo/CTF-style tool.
KNOWN_DOMAINS = {
    "google.com", "facebook.com", "paypal.com", "apple.com", "amazon.com",
    "microsoft.com", "netflix.com", "instagram.com", "linkedin.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "twitter.com",
    "x.com", "dropbox.com", "github.com", "gmail.com", "outlook.com",
    "yahoo.com", "ebay.com", "whatsapp.com", "spotify.com", "adobe.com",
}

# Characters that are commonly used to visually impersonate a letter.
# Each key maps to the letter it is meant to imitate.
HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "!": "i",
    "|": "l",
    "$": "s",
    "5": "s",
    "3": "e",
    "@": "a",
    "vv": "w",
    "rn": "m",
}

# Distance <= this value (after normalization) is considered suspicious,
# but exact matches (distance 0) are excluded - that's just the real domain.
DISTANCE_THRESHOLD = 2


def normalize_homoglyphs(domain: str) -> str:
    """Replace look-alike characters/sequences with the letter they imitate,
    and strip a leading 'www.' so it doesn't inflate the edit distance
    against known domains (which are stored without 'www.')."""
    normalized = domain.lower()
    if normalized.startswith("www."):
        normalized = normalized[4:]
    for fake, real in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def levenshtein_distance(a: str, b: str) -> int:
    """
    Compute the Levenshtein edit distance between two strings: the minimum
    number of single-character insertions, deletions, or substitutions
    needed to turn `a` into `b`. Implemented with the standard dynamic
    programming approach (no external library required).
    """
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row

    return previous_row[-1]


def find_closest_known_domain(hostname: str) -> tuple:
    """
    Compare the given hostname (after homoglyph normalization) against every
    domain in KNOWN_DOMAINS and return the closest match as
    (domain, distance). If hostname exactly matches a known domain, that
    domain is returned with distance 0 (not suspicious - it's the real thing).
    """
    normalized_hostname = normalize_homoglyphs(hostname or "")
    best_match = None
    best_distance = None

    for known in KNOWN_DOMAINS:
        distance = levenshtein_distance(normalized_hostname, known)
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_match = known

    return best_match, best_distance


def check_typosquatting(hostname: str) -> dict:
    """
    Run the typosquatting check on a hostname and return a result dict in
    the same shape as the checks in url_checker.py, so it can be merged
    into the same report/scoring pipeline.
    """
    if not hostname:
        return {"name": "Typosquatting", "flagged": False, "detail": "N/A"}

    closest_domain, distance = find_closest_known_domain(hostname)

    # Distance 0 means it either IS the known domain, or is visually
    # identical to it after homoglyph normalization - only flag if the
    # actual (non-normalized, but www-stripped) hostname differs from the
    # known domain.
    bare_hostname = hostname.lower()
    if bare_hostname.startswith("www."):
        bare_hostname = bare_hostname[4:]
    is_exact_real_domain = bare_hostname == closest_domain
    flagged = (0 < distance <= DISTANCE_THRESHOLD) or (distance == 0 and not is_exact_real_domain)

    if flagged:
        detail = (
            f"'{hostname}' closely resembles known domain '{closest_domain}' "
            f"(edit distance: {distance})"
        )
    else:
        detail = f"No close match to known domains (closest: {closest_domain}, distance: {distance})"

    return {
        "name": "Typosquatting",
        "flagged": flagged,
        "detail": detail,
    }
