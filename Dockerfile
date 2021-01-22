FROM rust:1.49 as builder

RUN USER=root cargo new --bin rust-docker-web
WORKDIR ./rust-docker-web
COPY ./Cargo.toml ./Cargo.toml
ENV DATABASE_URL=$DATABASE_URL
RUN env | grep DATABASE_URL
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/release/deps/wgman*
ENV DATABASE_URL=$DATABASE_URL
RUN env | grep DATABASE_URL
RUN cargo build --release


FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE $WGMAN_API_PORT

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /rust-docker-web/target/release/wgman ${APP}/wgman

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./wgman"]
