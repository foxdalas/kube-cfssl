FROM        alpine:3.5
MAINTAINER  Maxim Pogozhiy <foxdalas@gmail.com>

RUN addgroup -g 1000 app && \
    adduser -G app -h /home/app -u 1000 -D app

USER app
WORKDIR /home/app

COPY _build/cfssl-kube-linux-amd64 /cfssl-kube
ENTRYPOINT ["/cfssl-kube"]

ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/foxdalas/cfssl-kube" \
      org.label-schema.license="Apache-2.0"
