# clientmailforward

A client-side mail forwarder which uses IMAP IDLE to detect new messages and uploads them to a (different) IMAP server.

## Usage

```
Usage: clientmailforward [OPTIONS] --source-address <SOURCE_ADDRESS> --source-username <SOURCE_USERNAME> --target-address <TARGET_ADDRESS> --target-username <TARGET_USERNAME> <--source-password <SOURCE_PASSWORD>|--source-password-cmd <SOURCE_PASSWORD_CMD>|--source-token-cmd <SOURCE_TOKEN_CMD>> <--target-password <TARGET_PASSWORD>|--target-password-cmd <TARGET_PASSWORD_CMD>|--target-token-cmd <TARGET_TOKEN_CMD>>

Options:
      --source-address <SOURCE_ADDRESS>            source IMAP server address
      --source-port <SOURCE_PORT>                  source IMAP server port [default: 993]
      --source-username <SOURCE_USERNAME>          source IMAP server username
      --source-mailbox <SOURCE_MAILBOX>            source IMAP mailbox [default: INBOX]
      --source-password <SOURCE_PASSWORD>          source IMAP server password
      --source-password-cmd <SOURCE_PASSWORD_CMD>  source IMAP server password command
      --source-token-cmd <SOURCE_TOKEN_CMD>        source IMAP server OAuth2 token command
      --target-address <TARGET_ADDRESS>            target IMAP server address
      --target-port <TARGET_PORT>                  target IMAP server port [default: 993]
      --target-username <TARGET_USERNAME>          target IMAP server username
      --target-mailbox <TARGET_MAILBOX>            target IMAP mailbox [default: INBOX]
      --target-password <TARGET_PASSWORD>          target IMAP server password
      --target-password-cmd <TARGET_PASSWORD_CMD>  target IMAP server password command
      --target-token-cmd <TARGET_TOKEN_CMD>        target IMAP server OAuth2 token command
  -h, --help                                       Print help
  -V, --version                                    Print version
```
