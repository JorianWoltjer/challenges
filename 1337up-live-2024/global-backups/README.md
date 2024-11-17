# Global Backups

> The Administrator wanted a globally-accessible backup solution, but couldn't be asked to learn a new application. Luckily our front-end engineers helped him out to create a recognizable environment.

## Setup Notes

* **Multiple remote instances would be nice if not per user**, because players can interfere with each other. Mainly, when many different sessions access the website, these will all create files in `/tmp/sessions` that make the Admin sessions hard to find. This is easy to happen if players run a fuzzer like `ffuf`, but all anonymous sessions are removed after 60 seconds to help with this.
* For the above reason, also recomend players to **solve the challenge locally first**, before accessing the remote instance at all.
