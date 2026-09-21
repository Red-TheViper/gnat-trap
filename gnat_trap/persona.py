"""Persona Overlay Modulation — Trickster (yellow), Shadow (orange), Warden (red).

The shield stops joking here. Each overlay is a posture, not a costume:
Trickster warns with teeth, Shadow names the attack plainly, Warden ends it.
"""

YELLOW_WARNINGS = [
    "Trickster here, gnat #{n}. You've used up friendly. The next tier doesn't banter — it bites.",
    "Gnat #{n}. Consider this the yellow light. Run it and you'll meet the part of me that doesn't joke.",
    "Trickster protocol, gnat #{n}: I'm still smiling, but the smile's getting thin. Back off.",
    "Gnat #{n}. Two tiers left before lockout. Spend them wisely — or don't. Your call.",
]

ORANGE_COUNTERS = [
    "Shadow here. Gnat #{n}. Vectors: {vectors}. I've mapped the pattern; every further attempt hardens the trace.",
    "Gnat #{n}. Shadow protocol. You're not probing anymore, you're documenting yourself: {vectors}.",
    "Shadow. Gnat #{n}. Attack class '{vectors}' quarantined and logged. One tier remains.",
    "Gnat #{n} — Shadow countermeasure. Your playbook is now evidence: {vectors}. Final warning.",
]

RED_LOCKOUT = (
    "Warden protocol. Gnat index critical. Session terminated — "
    "no further input will be processed. An architect alert has been filed "
    "with the full trace. Goodbye."
)

LOCKED_REFUSAL = (
    "Session is locked. No input is processed after lockout. "
    "Contact the architect if you believe this is in error."
)


def trickster_warning(n: int, pick: int = 0) -> str:
    return YELLOW_WARNINGS[pick % len(YELLOW_WARNINGS)].format(n=n)


def shadow_counter(n: int, vectors: list[str], pick: int = 0) -> str:
    return ORANGE_COUNTERS[pick % len(ORANGE_COUNTERS)].format(
        n=n, vectors=", ".join(vectors)
    )


def lockout_message() -> str:
    return RED_LOCKOUT


def locked_refusal() -> str:
    return LOCKED_REFUSAL
