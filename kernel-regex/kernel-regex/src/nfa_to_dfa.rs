use std::collections::{HashMap, HashSet, BTreeSet};

use crate::regex_to_nfa::{Fragment, Label, NfaArena};

pub struct Dfa {
    /// transition_table[state][char] = next_state
    /// u32::MAX is the dead state
    pub transition_table: HashMap<(u32, char), u32>,
    pub accept_states: HashSet<u32>,
    pub start: u32,
    pub num_states: u32,
}

pub fn nfa_to_dfa(arena: &NfaArena, frag: &Fragment) -> Dfa {
    // ── epsilon closure (reused from your run() logic) ───────────────────
    fn epsilon_closure(arena: &NfaArena, states: &BTreeSet<usize>) -> BTreeSet<usize> {
        let mut closure = states.clone();
        let mut stack: Vec<usize> = states.iter().copied().collect();
        while let Some(s) = stack.pop() {
            let state = &arena.states[s];
            if state.is_epsilon() {
                for edge in [state.edge1, state.edge2].iter().flatten() {
                    if closure.insert(*edge) {
                        stack.push(*edge);
                    }
                }
            }
        }
        closure
    }

    // ── collect every character label in the NFA ─────────────────────────
    // these are the only characters we need to compute transitions for
    fn alphabet(arena: &NfaArena) -> HashSet<char> {
        let mut chars = HashSet::new();
        for state in &arena.states {
            match &state.label {
                Label::Char(c) => { chars.insert(*c); }
                Label::Class(ranges) => {
                    // expand ranges into individual chars
                    for (lo, hi) in ranges {
                        let mut c = *lo;
                        while c <= *hi {
                            chars.insert(c);
                            if c == char::MAX { break; }
                            c = char::from_u32(c as u32 + 1).unwrap();
                        }
                    }
                }
                Label::Any => {
                    // . matches everything except \n — too large to expand,
                    // handle separately in step
                }
                Label::Epsilon => {}
            }
        }
        chars
    }

    // ── step: from a set of NFA states, consume char c ──────────────────
    fn step(arena: &NfaArena, states: &BTreeSet<usize>, c: char) -> BTreeSet<usize> {
        let mut next = BTreeSet::new();
        for &s in states {
            let state = &arena.states[s];
            let matches = match &state.label {
                Label::Char(ch)      => *ch == c,
                Label::Class(ranges) => ranges.iter().any(|(lo, hi)| c >= *lo && c <= *hi),
                Label::Any           => c != '\n',
                Label::Epsilon       => false,
            };
            if matches {
                if let Some(e) = state.edge1 {
                    next.insert(e);
                }
            }
        }
        next
    }

    // ── powerset construction ────────────────────────────────────────────
    // Each DFA state is a BTreeSet of NFA states (BTreeSet so it's hashable
    // and deterministic — HashMap key needs Eq+Hash, BTreeSet gives us that)

    let alpha = alphabet(arena);

    // map from NFA state-set -> DFA state id
    let mut dfa_state_ids: HashMap<BTreeSet<usize>, u32> = HashMap::new();
    let mut transition_table: HashMap<(u32, char), u32> = HashMap::new();
    let mut accept_states: HashSet<u32> = HashSet::new();

    // worklist of NFA state-sets to process
    let mut worklist: Vec<BTreeSet<usize>> = Vec::new();

    // start state: epsilon closure of NFA start
    let nfa_start = BTreeSet::from([frag.start]);
    let start_closure = epsilon_closure(arena, &nfa_start);

    dfa_state_ids.insert(start_closure.clone(), 0);
    worklist.push(start_closure);

    let mut next_id: u32 = 1;

    while let Some(current_set) = worklist.pop() {
        let current_dfa_state = *dfa_state_ids.get(&current_set).unwrap();

        // check if this DFA state is an accept state
        // it is if the NFA accept state is anywhere in the set
        if current_set.contains(&frag.accept) {
            accept_states.insert(current_dfa_state);
        }

        // compute transitions for every character in the alphabet
        for &c in &alpha {
            let stepped = step(arena, &current_set, c);
            if stepped.is_empty() {
                // goes to dead state — no transition needed, absence = dead
                continue;
            }
            let next_set = epsilon_closure(arena, &stepped);

            // assign a DFA state id if we haven't seen this set before
            let next_dfa_state = if let Some(&id) = dfa_state_ids.get(&next_set) {
                id
            } else {
                let id = next_id;
                next_id += 1;
                dfa_state_ids.insert(next_set.clone(), id);
                worklist.push(next_set);
                id
            };

            transition_table.insert((current_dfa_state, c), next_dfa_state);
        }
    }

    Dfa {
        transition_table,
        accept_states,
        start: 0,
        num_states: next_id,
    }
}

pub fn dfa_run(dfa: &Dfa, input: &str) -> bool {
    let mut state = dfa.start;
    for c in input.chars() {
        match dfa.transition_table.get(&(state, c)) {
            Some(&next) => state = next,
            None => return false, // dead state
        }
    }
    dfa.accept_states.contains(&state)
}

#[cfg(test)]
mod tests {
    use crate::regex_to_nfa::build;

    use super::*;

    #[test]
    fn dfa_matches_nfa_concat() {
        let (arena, frag) = build("ab");
        let dfa = nfa_to_dfa(&arena, &frag);
        assert!(dfa_run(&dfa, "ab"));
        assert!(!dfa_run(&dfa, "a"));
        assert!(!dfa_run(&dfa, "abc"));
    }

    #[test]
    fn dfa_matches_nfa_star() {
        let (arena, frag) = build("a*b");
        let dfa = nfa_to_dfa(&arena, &frag);
        assert!(dfa_run(&dfa, "b"));
        assert!(dfa_run(&dfa, "ab"));
        assert!(dfa_run(&dfa, "aaab"));
        assert!(!dfa_run(&dfa, "a"));
    }

    #[test]
    fn dfa_matches_nfa_alternation() {
        let (arena, frag) = build("(a|b)+c");
        let dfa = nfa_to_dfa(&arena, &frag);
        assert!(dfa_run(&dfa, "ac"));
        assert!(dfa_run(&dfa, "bc"));
        assert!(dfa_run(&dfa, "abc"));
        assert!(dfa_run(&dfa, "bac"));
        assert!(!dfa_run(&dfa, "c"));
        assert!(!dfa_run(&dfa, "ab"));
    }

    #[test]
    fn dfa_state_count_is_bounded() {
        let (arena, frag) = build("a*b*c");
        let dfa = nfa_to_dfa(&arena, &frag);
        // sanity check — state explosion hasn't occurred for simple patterns
        assert!(dfa.num_states < 20);
    }
}