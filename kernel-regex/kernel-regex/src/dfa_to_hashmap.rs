use std::collections::{HashMap, HashSet};

use crate::nfa_to_dfa::Dfa;

pub struct DfaMap {
    /// key: state * 256 + byte, value: next_state
    pub transitions: HashMap<u32, u32>,
    pub accept_states: HashSet<u32>,
    pub num_states: u32,
    pub num_transitions: u32,  // use as max_entries for BPF hash map
}

pub fn dfa_to_map(dfa: &Dfa) -> DfaMap {
    let mut transitions = HashMap::new();

    for (&(state, c), &next) in &dfa.transition_table {
        let key = state * 256 + c as u32;
        transitions.insert(key, next);
    }

    DfaMap {
        num_transitions: transitions.len() as u32,
        transitions,
        accept_states: dfa.accept_states.clone(),
        num_states: dfa.num_states,
    }
}

pub fn map_run(dfa_map: &DfaMap, input: &str) -> bool {
    let mut state: u32 = 0;
    for c in input.chars() {
        let key = state * 256 + c as u32;
        match dfa_map.transitions.get(&key) {
            Some(&next) => state = next,
            None => return false,
        }
    }
    dfa_map.accept_states.contains(&state)
}