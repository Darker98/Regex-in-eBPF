use std::collections::HashMap;

fn insert_concat(infix: &str) -> String {
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

pub fn postfix(re: &str) -> Vec<char> {
    shunt(re)
}
