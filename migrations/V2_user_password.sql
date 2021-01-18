-- Table: public.UserPassword

-- DROP TABLE public."UserPassword";

CREATE TABLE public."UserPassword"
(
    id uuid NOT NULL,
    password_hash character varying(128) COLLATE pg_catalog."default" NOT NULL,
    salt character varying(128) COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "Password_pkey" PRIMARY KEY (id),
    CONSTRAINT id FOREIGN KEY (id)
        REFERENCES public."User" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)

TABLESPACE pg_default;

ALTER TABLE public."UserPassword"
    OWNER to postgres;
