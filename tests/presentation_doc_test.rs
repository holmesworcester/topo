use std::fs;
use std::path::Path;

fn deck_text() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("docs/topo-presentation.md")).expect("read presentation deck")
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn deck_describes_context_facts_and_needs_offers() {
    let deck = deck_text();
    let normalized = normalize_whitespace(&deck);

    for required in [
        "title: Context demo presentation",
        "# Context",
        "facts offer context to other facts",
        "Context relationships can be exact facts, fact ranges, or offers waiting for future facts",
        "Context needs/offers",
        "Connection, sync, and auth are facts too",
        "# How context needs/offers work",
        "A need is a role, scope, and byte range; an offer is the same shape",
        "Offers can exist before the facts that will need them",
        "flowchart LR",
        "flowchart TD",
        "Fact Sync Throughput",
        "Context-Match Cascade",
        "con send \"hello\"",
        "share_fact_with_sync",
    ] {
        assert!(
            normalized.contains(required),
            "presentation deck is missing Context framing {required:?}"
        );
    }

    assert!(
        deck.matches("```mermaid").count() >= 2,
        "presentation deck should keep GitHub-compatible Mermaid diagrams"
    );
}

#[test]
fn deck_does_not_use_poc7_or_event_model_framing() {
    let deck = deck_text();

    for forbidden in [
        "poc-7",
        "POC-7",
        "# Topo",
        "Topo-sort",
        "Event Sync Throughput",
        "event set",
        "events with dependencies",
        "Events turn into SQLite tables",
    ] {
        assert!(
            !deck.contains(forbidden),
            "presentation deck should describe Context instead of prior framing {forbidden:?}"
        );
    }

    let event_terms = deck
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|term| term.eq_ignore_ascii_case("event") || term.eq_ignore_ascii_case("events"))
        .collect::<Vec<_>>();
    assert!(
        event_terms.is_empty(),
        "presentation deck should use fact terminology, not event terminology"
    );
}
