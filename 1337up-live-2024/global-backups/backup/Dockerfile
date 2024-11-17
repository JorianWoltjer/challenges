FROM alpine:latest

RUN apk add --no-cache openssh

WORKDIR /home/admin
RUN mkdir /var/run/sshd
RUN adduser -u 1337 -D admin && passwd -u admin
RUN mkdir .ssh && chown admin:admin .ssh
RUN mkdir files && chown admin:admin files

RUN ssh-keygen -A
RUN echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/usr/sbin/sshd", "-D" ]
