use std::env;

fn main() {
    match secret_bento::run(env::args().collect()) {
        Ok(outcome) => std::process::exit(outcome.exit_code().as_i32()),
        Err(error) => {
            eprintln!("error: {}", error.message());
            std::process::exit(error.exit_code().as_i32());
        }
    }
}
