FROM ubuntu:22.04

RUN mkdir /home/ctf

COPY chall /home/ctf/
COPY run.sh /home/ctf/
COPY flag.txt /home/ctf/
COPY flag_root.txt /root

RUN adduser ctf && \
    chown root:root /home/ctf/chall && \
    chmod +x /home/ctf/chall && \
    chmod u+s /home/ctf/chall && \
    chown ctf:ctf /home/ctf/flag.txt

RUN chmod +x /home/ctf/run.sh && \
    chmod o+r /home/ctf/run.sh

RUN dpkg --add-architecture i386 && \
    apt update && apt install -y ncat libc6:i386


CMD ["su","ctf","-c","/home/ctf/run.sh"]

