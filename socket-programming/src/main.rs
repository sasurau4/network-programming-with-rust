use std::env;
#[macro_use]
extern crate log;


fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        error!("Please specify [tcp|udp] [server|client] [addr:port].");
        std::process::exit(1);

    }

    let protocol: &str = &args[1];
    let role: &str = &args[2];
    let address = &args[3];
    match protocol {
        "tcp" => match role {
            "server" => {
                // TODO: call tcp server
            }
            "client" => {
                // TODO: call tcp client
            }
            _ => {
                missing_role();
            }

        }
        "udp" => match role {
            "server" => {
                // TODO: call udp server
            }
            "client" => {
                // TODO: call udp client
            }
            _ => {
                missing_role();
            }

        }
        _ => {
            error!("Please specify tcp or udp on the 1st argument.");
            std::process::exit(1);
        }
    }
}

/**
 * Function that emit error when the 2nd argument is invalid
 */
fn missing_role() {
    error!("Please specify server or client on the 2nd argument.");
    std::process::exit(1);
}