import re
from typing import Any


LAW_ALIASES = {
    "betrvg": "gesetz-betrvg",
    "arbzg": "gesetz-arbzg",
    "arbschg": "gesetz-arbschg",
    "arbeitsschutzgesetz": "gesetz-arbschg",
    "kschg": "gesetz-kschg",
    "agg": "gesetz-agg",
    "bdsg": "gesetz-bdsg",
    "dsgvo": "gesetz-dsgvo",
    "ds-gvo": "gesetz-dsgvo",
    "datenschutz-grundverordnung": "gesetz-dsgvo",
    "sgb i": "gesetz-sgb-i",
    "sgb 1": "gesetz-sgb-i",
    "sgb iii": "gesetz-sgb-iii",
    "sgb 3": "gesetz-sgb-iii",
    "sgb iv": "gesetz-sgb-iv",
    "sgb 4": "gesetz-sgb-iv",
    "sgb v": "gesetz-sgb-v",
    "sgb 5": "gesetz-sgb-v",
    "sgb vi": "gesetz-sgb-vi",
    "sgb 6": "gesetz-sgb-vi",
    "sgb ix": "gesetz-sgb-ix",
    "sgb 9": "gesetz-sgb-ix",
    "sgb x": "gesetz-sgb-x",
    "sgb 10": "gesetz-sgb-x",
    "burlg": "gesetz-burlg",
    "tzbfg": "gesetz-tzbfg",
    "tvg": "gesetz-tvg",
    "arbgg": "gesetz-arbgg",
    "muschg": "gesetz-muschg",
    "beeg": "gesetz-beeg",
    "hinschg": "gesetz-hinschg",
    "nachwg": "gesetz-nachwg",
    "entgfg": "gesetz-entgfg",
    "entgeltfortzahlungsgesetz": "gesetz-entgfg",
    "wahlordnung": "gesetz-betrvg-wo",
    "betrvgdv1wo": "gesetz-betrvg-wo",
    "milog": "gesetz-milog",
    "aüg": "gesetz-aueg",
    "aueg": "gesetz-aueg",
}


def norm_locator(source_uid: str | None, value: str) -> str:
    if source_uid == "gesetz-dsgvo":
        return "Art. " + value
    return "§ " + value


def detect_law_refs(question: str) -> list[tuple[str, str]]:
    q = question.lower()
    refs: list[tuple[str, str]] = []
    paragraph_matches = re.findall(r"§\s*([0-9]+[a-z]?)", q)
    article_matches = re.findall(r"(?:art\.?|artikel)\s*([0-9]+[a-z]?)", q)
    for alias, source_uid in sorted(LAW_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        alias_pattern = re.escape(alias).replace(r"\ ", r"\s+")
        if re.search(r"(?<![0-9a-zäöüß])" + alias_pattern + r"(?![0-9a-zäöüß])", q):
            matches = article_matches if source_uid == "gesetz-dsgvo" and article_matches else paragraph_matches
            for locator in matches:
                refs.append((source_uid, locator))
    # If paragraph is mentioned without law, still allow broad exact paragraph lookup.
    if not refs:
        for para in paragraph_matches:
            refs.append(("", para))
    return refs


def concise_source_statement(chunk: dict[str, Any], max_len: int = 900) -> str:
    content = (chunk.get("content") or "").strip()
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    text = " ".join(lines)
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def fallback_keywords(question: str) -> list[str]:
    """Conservative keyword fallback for tariff/legal retrieval.

    PostgreSQL plainto_tsquery can become too strict for long natural-language
    questions. This returns distinctive terms only; generic short words are
    ignored.
    """
    terms = re.findall(r"[A-Za-zÄÖÜäöüß0-9][A-Za-zÄÖÜäöüß0-9._/-]{3,}", question)
    stop = {
        "steht", "freigegebenen", "quellen", "tarifquellen", "amtlichen",
        "quelle", "antwort", "bitte", "was", "wird", "werden", "dazu",
        "nach", "über", "ueber", "eine", "einer", "einen", "und", "oder",
    }
    out: list[str] = []
    for term in terms:
        normalized = term.strip(" .,:;!?()[]{}\"'")
        if not normalized or normalized.lower() in stop:
            continue
        if normalized not in out:
            out.append(normalized)
    return out[:8]


def distinctive_keywords(question: str, limit: int = 5) -> list[str]:
    """Return terms suitable for a conservative AND-style fallback search."""
    generic = {
        "freigegebenen", "tarifquellen", "amtlichen", "quellen", "quelle",
        "steht", "frage", "antwort", "bitte", "dazu", "nach", "ueber",
        "über", "eine", "einer", "einen", "und", "oder", "zur", "zum",
        "der", "die", "das", "den", "dem", "des", "was", "wird", "werden",
    }
    terms = []
    for term in fallback_keywords(question):
        normalized = term.strip(" .,:;!?()[]{}\"'")
        if len(normalized) < 5:
            continue
        if normalized.lower() in generic:
            continue
        if normalized not in terms:
            terms.append(normalized)
    return terms[:limit]


def chunk_source_key(chunk: dict[str, Any]) -> str:
    """Return a stable source grouping key for retrieval de-duplication."""
    document_sha256 = (chunk.get("document_sha256") or "").strip()
    if document_sha256:
        return "sha256:" + document_sha256
    source_uid = (chunk.get("source_uid") or "").strip()
    if source_uid:
        return source_uid
    internal_ref = (chunk.get("internal_ref") or "").strip()
    if ":" in internal_ref:
        prefix = internal_ref.split(":", 1)[0].strip()
        if prefix:
            return prefix
    if internal_ref:
        return internal_ref
    citation_url = (chunk.get("citation_url") or "").strip()
    if citation_url:
        return citation_url
    return (chunk.get("citation_label") or "unknown-source").strip()


def diverse_chunks(
    chunks: list[dict[str, Any]],
    max_total: int,
    per_source_limit: int = 2,
    class_limits: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Deduplicate chunks and cap how much one source can dominate an answer.

    The function preserves retrieval order, removes duplicate chunk IDs, then
    applies conservative source/class caps. It is intentionally deterministic:
    no source is silently preferred except by the already established retrieval
    ranking.
    """
    seen_chunks: set[Any] = set()
    source_counts: dict[str, int] = {}
    document_sha_sources: dict[str, str] = {}
    class_counts: dict[str, int] = {}
    selected: list[dict[str, Any]] = []

    for chunk in chunks:
        chunk_key = chunk.get("chunk_id") or chunk.get("chunk_uid") or chunk.get("citation_label")
        if chunk_key in seen_chunks:
            continue
        document_sha256 = (chunk.get("document_sha256") or "").strip()
        source_uid = (chunk.get("source_uid") or "").strip()
        if document_sha256 and source_uid:
            chosen_source = document_sha_sources.get(document_sha256)
            if chosen_source and chosen_source != source_uid:
                continue
        source_key = chunk_source_key(chunk)
        source_count = source_counts.get(source_key, 0)
        if source_count >= per_source_limit:
            continue
        source_class = chunk.get("source_class") or ""
        if class_limits and source_class in class_limits and class_counts.get(source_class, 0) >= class_limits[source_class]:
            continue

        selected.append(chunk)
        seen_chunks.add(chunk_key)
        if document_sha256 and source_uid:
            document_sha_sources.setdefault(document_sha256, source_uid)
        source_counts[source_key] = source_count + 1
        if source_class:
            class_counts[source_class] = class_counts.get(source_class, 0) + 1
        if len(selected) >= max_total:
            break

    return selected
