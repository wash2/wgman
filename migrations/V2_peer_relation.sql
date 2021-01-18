-- Table: public.PeerRelation

-- DROP TABLE public."PeerRelation";

CREATE TABLE public."PeerRelation"
(
    endpoint uuid NOT NULL,
    peer uuid NOT NULL,
    peer_allowed_ip inet[] NOT NULL DEFAULT '{}'::inet[],
    endpoint_allowed_ip inet[] NOT NULL DEFAULT '{}'::inet[],
    CONSTRAINT peer_relation PRIMARY KEY (endpoint, peer)
        INCLUDE(endpoint, peer),
    CONSTRAINT client FOREIGN KEY (peer)
        REFERENCES public."Interface" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID,
    CONSTRAINT server FOREIGN KEY (endpoint)
        REFERENCES public."Interface" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)

TABLESPACE pg_default;

ALTER TABLE public."PeerRelation"
    OWNER to postgres;

COMMENT ON CONSTRAINT peer_relation ON public."PeerRelation"
    IS 'client-server pair';
