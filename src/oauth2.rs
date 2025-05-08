pub(crate) struct OAuth2 {
    pub(crate) user: String,
    pub(crate) access_token: String,
}

impl async_imap::Authenticator for &OAuth2 {
    type Response = String;
    fn process(&mut self, _: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}
