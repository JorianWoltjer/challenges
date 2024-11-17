FROM oven/bun:1.1.8

RUN apt-get update && apt-get install -y openssh-client curl gcc

WORKDIR /app
RUN adduser -u 1337 --disabled-password --gecos '' user
COPY package.json bun.lockb ./
RUN bun install

COPY src ./src
COPY views ./views
COPY public ./public

RUN mkdir /tmp/files && chown user /tmp/files

WORKDIR /home/user/.ssh
RUN ssh-keygen -t ed25519 -f id_ed25519 -N ''
RUN echo 'StrictHostKeyChecking=accept-new' > config
RUN chown -R user:user .

COPY flag.txt readflag.c /
RUN gcc /readflag.c -o /readflag
RUN chmod 400 /flag.txt && chmod +s /readflag

WORKDIR /app
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

USER user
ENV NODE_ENV=production

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "bun", "run", "src/index.ts" ]
