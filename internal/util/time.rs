use chrono::{DateTime, Utc};

pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::now_utc;
    use chrono::Utc;

    #[test]
    fn now_utc_returns_current_time() {
        let before = Utc::now();
        let now = now_utc();
        let after = Utc::now();
        assert!(now >= before);
        assert!(now <= after);
    }
}
