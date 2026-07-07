use eat_pass_core::mailbox::{canonical_email, mailbox_measurement};

fn main() {
    for (key_fill, addr) in [
        (1u8, "alice@example.com"),
        (1u8, "bob@example.com"),
        (2u8, "alice@example.com"),
        (9u8, "  User@Example.COM "),
    ] {
        let canonical = canonical_email(addr).unwrap();
        let m = mailbox_measurement(&[key_fill; 32], &canonical);
        println!("{} {} {} {}", key_fill, addr.replace(' ', "_"), canonical, hex::encode(&m.value_x));
    }
}
