# My CTF Challenges

This repository hold a collection of all Capture The Flag challenges I've made for public events. Each event has its own directory with challenges. Challenges all include source code and a `solve/` folder with a writeup and solve script. 

Any challenge can be started with the following command inside its directory (assuming you have [Docker](https://www.docker.com/)):

```sh
docker compose up --build
```

For a fully authentic experience, each challenge also has a `release.sh` script that packs the challenge into ZIP files including a "*_handout.zip" file containing what will be given to players as source code.

## Events

#### [1337UP LIVE CTF 2024](1337up-live-2024)

https://ctftime.org/event/2446

* [Web - Global Backups](1337up-live-2024/global-backups): 1 solve (server-side, Bun Shell globbing, Express sessions, Argument Injection)
* [Crypto - Conversationalist](1337up-live-2024/conversationalist): 20 solves (cocoon encryption, AES-GCM, nonce-reuse)

---
