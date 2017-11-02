FROM        alpine:3.5
MAINTAINER  Maxim Pogozhiy <foxdalas@gmail.com>

RUN addgroup -g 1000 app && \
    adduser -G app -h /home/app -u 1000 -D app

USER app
WORKDIR /home/app

COPY _build/kube-cfssl-linux-amd64 /kube-cfssl
ENTRYPOINT ["/kube-cfssl"]

ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/foxdalas/kube-cfssl" \
      org.label-schema.license="Apache-2.0"
