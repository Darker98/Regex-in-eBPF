use std::{collections::HashMap};

pub fn insert_concat(infix: &str) -> String {
    let specials = ['*', '+', '?', '|', '(', ')'];
    let mut result = String::new();
    let chars: Vec<char> = infix.chars().collect();

    for i in 0..chars.len() {
        let c = chars[i];
        result.push(c);

        if i + 1 < chars.len() {
            let next = chars[i + 1];
            // insert '.' between two atoms, or after quantifier before atom
            let left_ok  = !matches!(c, '|' | '(');
            let right_ok = !matches!(next, '|' | ')' | '*' | '+' | '?');
            if left_ok && right_ok {
                result.push('.');
            }
        }
    }
    result
}

fn shunt(infix_original: &str) -> Vec<char> {
    let mut specials: HashMap<char, u8> = HashMap::new();

    specials.insert('*', 60);
    specials.insert('+', 55);
    specials.insert('?', 50);
    specials.insert('.', 40);
    specials.insert('|', 20);

    let mut infix = insert_concat(infix_original);

    let mut postfix: Vec<char> = Vec::new();
    let mut stack: Vec<char> = Vec::new();

    for c in infix.chars() {
        // Open bracket
        if c.eq(&'(') {
            stack.push(c);
        }

        // Closed bracket
        else if c.eq(&')') {
            while stack[stack.len() - 1] != '(' {
                postfix.push(stack[stack.len() - 1]);
                stack.pop();
            }
            stack.pop();
        }

        // Special character
        else if specials.contains_key(&c) {
            while !stack.is_empty() && (specials.get(&c).or_else(|| Some(&0)) <= specials.get(&stack[stack.len() - 1]).or_else(|| Some(&0))) {
                postfix.push(stack[stack.len() - 1]);
                stack.pop();
            }
            stack.push(c);
        }

        // Regular character
        else {
            postfix.push(c);
        }
    }

    while !stack.is_empty() {
        postfix.push(stack[stack.len() - 1]);
        stack.pop();
    }

    postfix
}

pub enum Label {
    Epsilon,
    Char(char),
    Class(Vec<(char, char)>),  // list of ranges
    Any,                        // . wildcard
}

pub struct State {
    pub label: Label,
    pub edge1: Option<usize>,
    pub edge2: Option<usize>
}

impl State {
    pub fn new() -> State {
        State {
            label: Label::Epsilon,
            edge1: None,
            edge2: None
        }
    }

    pub fn is_epsilon(&self) -> bool {
        match self.label {
            Label::Epsilon => true,
            _ => false
        }
    }
}

pub struct NfaArena {
    pub states: Vec<State>,
}

impl NfaArena {
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    pub fn new_state(&mut self) -> usize {
        let id = self.states.len();
        self.states.push(State::new());
        id
    }
}

// NFA fragment is just two indices into the arena
pub struct Fragment {
    pub start: usize,
    pub accept: usize,
}

pub fn compile(postfix: &[char], arena: &mut NfaArena) -> Fragment {
    let mut stack: Vec<Fragment> = Vec::new();

    for &c in postfix {
        match c {
            '*' => {
                let f = stack.pop().unwrap();
                let s = arena.new_state();
                let a = arena.new_state();
                // s -> f.start, s -> a (skip), f.accept -> f.start (loop), f.accept -> a
                arena.states[s].edge1 = Some(f.start); 
                arena.states[s].edge2 = Some(a); 
                arena.states[f.accept].edge1 = Some(f.start); 
                arena.states[f.accept].edge2 = Some(a);
                stack.push(Fragment { start: s, accept: a });
            }
            '|' => {
                let f2 = stack.pop().unwrap();
                let f1 = stack.pop().unwrap();
                let s = arena.new_state();
                let a = arena.new_state();
                arena.states[s].edge1 = Some(f1.start); // enter 1
                arena.states[s].edge2 = Some(f2.start); // enter 2
                arena.states[f1.accept].edge1 = Some(a); // exit 1
                arena.states[f2.accept].edge1 = Some(a); // exit 2
                stack.push(Fragment { start: s, accept: a });
            }
            '.' => {
                let f2 = stack.pop().unwrap();
                let f1 = stack.pop().unwrap();
                // wire f1.accept -> f2.start via epsilon
                arena.states[f1.accept].edge1 = Some(f2.start);
                stack.push(Fragment { start: f1.start, accept: f2.accept });
            }
            '+' => {
                // r+ = r · r* : must match at least once
                let f = stack.pop().unwrap();
                let s = arena.new_state();
                let a = arena.new_state();
                arena.states[s].edge1 = Some(f.start);          // enter
                arena.states[f.accept].edge1 = Some(f.start);   // loop
                arena.states[f.accept].edge2 = Some(a);         // exit
                stack.push(Fragment { start: s, accept: a });
            }
            '?' => {
                let f = stack.pop().unwrap();
                let s = arena.new_state();
                let a = arena.new_state();
                arena.states[s].edge1 = Some(f.start);
                arena.states[s].edge2 = Some(a);  // skip
                arena.states[f.accept].edge1 = Some(a);
                stack.push(Fragment { start: s, accept: a });
            }
            // literal character
            c => {
                let s = arena.new_state();
                let a = arena.new_state();
                arena.states[s].label = Label::Char(c);
                arena.states[s].edge1 = Some(a);
                stack.push(Fragment { start: s, accept: a });
            }
        }
    }

    stack.pop().unwrap()
}

fn postfix(re: &str) -> Vec<char> {
    shunt(re)
}

pub fn build(re: &str) -> (NfaArena, Fragment) {
    let mut arena = NfaArena::new();
    let pf = postfix(re);
    let frag = compile(&pf, &mut arena);
    (arena, frag)
}


#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────



    /// Walk the NFA and check whether `input` is accepted.
    /// This is a simple recursive epsilon-closure simulation — not efficient,
    /// but correct enough for testing Thompson construction.
    fn accepts(arena: &NfaArena, frag: &Fragment, input: &str) -> bool {
        fn step(arena: &NfaArena, state: usize, chars: &[char]) -> bool {
            if chars.is_empty() {
                // are we at accept, or can we epsilon-reach it?
                return state == usize::MAX || epsilon_reach(arena, state, chars);
            }
            let s = &arena.states[state];
            match s.label {
                // epsilon state — follow edges without consuming input
                Label::Epsilon => {
                    let e1 = s.edge1.map_or(false, |n| step(arena, n, chars));
                    let e2 = s.edge2.map_or(false, |n| step(arena, n, chars));
                    e1 || e2
                }
                // labelled state — consume one char if it matches
                Label::Char(c) => {
                    if c == chars[0] {
                        s.edge1.map_or(false, |n| step(arena, n, &chars[1..]))
                    } else {
                        false
                    }
                }
                _ => false
            }
        }

        // separate epsilon-only reach check for accept detection
        fn epsilon_reach(arena: &NfaArena, state: usize, chars: &[char]) -> bool {
            let s = &arena.states[state];
            if !s.is_epsilon() {
                return false; // labelled — can't epsilon past it
            }
            let e1 = s.edge1.map_or(false, |n| {
                if n == usize::MAX { true } else { epsilon_reach(arena, n, chars) }
            });
            let e2 = s.edge2.map_or(false, |n| {
                if n == usize::MAX { true } else { epsilon_reach(arena, n, chars) }
            });
            e1 || e2
        }

        let chars: Vec<char> = input.chars().collect();
        step(arena, frag.start, &chars)
    }

    /// Simpler accept check: just simulate state sets (correct NFA simulation)
    fn run(arena: &NfaArena, frag: &Fragment, input: &str) -> bool {
        use std::collections::HashSet;

        fn epsilon_closure(arena: &NfaArena, states: HashSet<usize>) -> HashSet<usize> {
            let mut closure = states.clone();
            let mut stack: Vec<usize> = states.into_iter().collect();
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

        fn step(arena: &NfaArena, states: &HashSet<usize>, c: char) -> HashSet<usize> {
            let mut next = HashSet::new();
            for &s in states {
                let state = &arena.states[s];
                let matches = match &state.label {
                    Label::Char(ch)    => *ch == c,
                    Label::Class(ranges) => ranges.iter().any(|(lo, hi)| c >= *lo && c <= *hi),
                    Label::Any         => c != '\n',
                    Label::Epsilon     => false,
                };
                if matches {
                    if let Some(e) = state.edge1 { next.insert(e); }
                }
            }
            next
        }

        let mut current = epsilon_closure(arena, HashSet::from([frag.start]));
        for c in input.chars() {
            current = epsilon_closure(arena, step(arena, &current, c));
            if current.is_empty() { return false; }
        }
        current.contains(&frag.accept)
    }

    // ── insert_concat ────────────────────────────────────────────────────────

    #[test]
    fn concat_inserts_dot_between_literals() {
        assert_eq!(insert_concat("ab"), "a.b");
    }

    #[test]
    fn concat_no_dot_after_pipe() {
        assert_eq!(insert_concat("a|b"), "a|b");
    }

    #[test]
    fn concat_no_dot_before_quantifier() {
        assert_eq!(insert_concat("ab*"), "a.b*");
    }

    #[test]
    fn concat_after_quantifier_before_literal() {
        assert_eq!(insert_concat("a*b"), "a*.b");
    }

    #[test]
    fn concat_group() {
        assert_eq!(insert_concat("a(bc)"), "a.(b.c)");
    }

    // ── shunt (postfix) ──────────────────────────────────────────────────────

    #[test]
    fn postfix_simple_concat() {
        // ab -> a.b -> ab.  (postfix)
        assert_eq!(postfix("ab"), vec!['a', 'b', '.']);
    }

    #[test]
    fn postfix_alternation() {
        // a|b -> ab|
        assert_eq!(postfix("a|b"), vec!['a', 'b', '|']);
    }

    #[test]
    fn postfix_star() {
        // a* -> a*
        assert_eq!(postfix("a*"), vec!['a', '*']);
    }

    #[test]
    fn postfix_concat_and_star() {
        // ab* -> a.b* -> ab*.
        assert_eq!(postfix("ab*"), vec!['a', 'b', '*', '.']);
    }

    #[test]
    fn postfix_group_changes_precedence() {
        // (a|b)c -> (a|b).c -> ab|c.
        assert_eq!(postfix("(a|b)c"), vec!['a', 'b', '|', 'c', '.']);
    }

    // ── NFA acceptance ───────────────────────────────────────────────────────

    #[test]
    fn nfa_single_literal() {
        let (arena, frag) = build("a");
        assert!(run(&arena, &frag, "a"));
        assert!(!run(&arena, &frag, "b"));
        assert!(!run(&arena, &frag, ""));
    }

    #[test]
    fn nfa_concat() {
        let (arena, frag) = build("ab");
        assert!(run(&arena, &frag, "ab"));
        assert!(!run(&arena, &frag, "a"));
        assert!(!run(&arena, &frag, "b"));
        assert!(!run(&arena, &frag, "abc"));
    }

    #[test]
    fn nfa_alternation() {
        let (arena, frag) = build("a|b");
        assert!(run(&arena, &frag, "a"));
        assert!(run(&arena, &frag, "b"));
        assert!(!run(&arena, &frag, "ab"));
        assert!(!run(&arena, &frag, ""));
    }

    #[test]
    fn nfa_star_zero_times() {
        let (arena, frag) = build("a*");
        assert!(run(&arena, &frag, ""));
        assert!(run(&arena, &frag, "a"));
        assert!(run(&arena, &frag, "aaa"));
        assert!(!run(&arena, &frag, "b"));
    }

    #[test]
    fn nfa_plus_one_or_more() {
        let (arena, frag) = build("a+");
        assert!(!run(&arena, &frag, ""));
        assert!(run(&arena, &frag, "a"));
        assert!(run(&arena, &frag, "aaa"));
        assert!(!run(&arena, &frag, "b"));
    }

    #[test]
    fn nfa_question_zero_or_one() {
        let (arena, frag) = build("a?");
        assert!(run(&arena, &frag, ""));
        assert!(run(&arena, &frag, "a"));
        assert!(!run(&arena, &frag, "aa"));
    }

    #[test]
    fn nfa_grouped_alternation() {
        let (arena, frag) = build("(a|b)c");
        assert!(run(&arena, &frag, "ac"));
        assert!(run(&arena, &frag, "bc"));
        assert!(!run(&arena, &frag, "c"));
        assert!(!run(&arena, &frag, "ab"));
    }

    #[test]
    fn nfa_complex_pattern() {
        // matches "a" followed by one or more "b|c"
        let (arena, frag) = build("a(b|c)+");
        assert!(run(&arena, &frag, "ab"));
        assert!(run(&arena, &frag, "ac"));
        assert!(run(&arena, &frag, "abbc"));
        assert!(run(&arena, &frag, "acbc"));
        assert!(!run(&arena, &frag, "a"));
        assert!(!run(&arena, &frag, "b"));
    }

    #[test]
    fn nfa_star_concat() {
        // a*b — zero or more a, then b
        let (arena, frag) = build("a*b");
        assert!(run(&arena, &frag, "b"));
        assert!(run(&arena, &frag, "ab"));
        assert!(run(&arena, &frag, "aaab"));
        assert!(!run(&arena, &frag, "a"));
        assert!(!run(&arena, &frag, ""));
    }
}